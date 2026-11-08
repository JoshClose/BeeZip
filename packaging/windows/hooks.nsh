; Installer hooks for Tauri's NSIS template (docs/M3.md §5.5, M4 §9): put $INSTDIR\bin, which
; holds beezip.exe, on the user's PATH and add BeeZip to Explorer's menu, and on uninstall take
; both away again. `cargo xtask dist` defines BEEZIP_SHELL_DLL, this version's menu DLL.
;
; PowerShell edits PATH rather than NSIS, whose strings hold 1 024 characters in its default
; build: a longer PATH would be cut. The script reads the value unexpanded (so %USERPROFILE%
; and the like survive) and writes it back as REG_EXPAND_SZ. It keeps empty segments, so a
; trailing `;` survives and uninstalling gives back exactly the PATH there was. Deleting a
; variable that doesn't exist then makes .NET broadcast WM_SETTINGCHANGE, so new shells see it.
;
; The folder reaches the script through the BEEZIP_BIN environment variable, so no path needs
; quoting. In NSIS strings `$$` is a literal `$`; the script has no double quotes.

!macro NSIS_HOOK_POSTINSTALL
  System::Call 'Kernel32::SetEnvironmentVariable(t "BEEZIP_BIN", t "$INSTDIR\bin")'
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = $$env:BEEZIP_BIN.TrimEnd('\'); $$k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment'); $$p = [string]$$k.GetValue('Path', '', 'DoNotExpandEnvironmentNames'); $$parts = [System.Collections.Generic.List[string]]$$p.Split(';'); if (-not ($$parts | Where-Object { $$_.TrimEnd('\') -eq $$d })) { if ($$parts[$$parts.Count - 1] -eq '') { $$parts.Insert($$parts.Count - 1, $$d) } else { $$parts.Add($$d) }; $$k.SetValue('Path', ($$parts -join ';'), 'ExpandString'); [Environment]::SetEnvironmentVariable('BEEZIP_PATH_REFRESH', $$null, 'User') }"`
  Pop $0
  ; Explorer's menu, for this user (docs/M4.md §5.3): on Windows 11, its own menu when this
  ; installer carries the signed package (`xtask dist --sign-dev`) and Windows trusts its
  ; certificate, and otherwise the classic menu. It also deletes the DLLs an older version left,
  ; or has Windows delete them at the next sign-in while Explorer still holds them (§5.6).
  nsExec::ExecToLog `"$INSTDIR\bin\beezip.exe" shell install --dll "$INSTDIR\${BEEZIP_SHELL_DLL}" --app "$INSTDIR\BeeZip.exe"`
  Pop $0
!macroend

; File associations. On uninstall, Tauri's APP_UNASSOCIATE writes back the default it saved at
; install time, even when that was nothing, and leaves its `_backup` value: the empty default then
; hides the machine-wide handler (Windows' own ArchiveFolder). And if another app has taken an
; extension since, it puts the stale value back over it. So before it runs, the backup becomes
; what the extension has now, when that isn't BeeZip; and afterwards the backup value goes, as
; does a default that is empty or still BeeZip's, and a key that is then empty.
; `cargo xtask dist` appends BEEZIP_FOR_EACH_ASSOCIATION, generated from formats.list.

!macro BEEZIP_KEEP_CURRENT EXT FILECLASS
  ReadRegStr $R0 SHCTX "Software\Classes\.${EXT}" ""
  StrCmp $R0 "${FILECLASS}" +2 0
  WriteRegStr SHCTX "Software\Classes\.${EXT}" "${FILECLASS}_backup" "$R0"
!macroend

; An upgrade runs APP_ASSOCIATE again, which saves the current default as the backup: by then
; BeeZip's own, so the default from before BeeZip was lost (M3 #51). Before it runs, each
; extension whose default is still BeeZip's gets its saved backup back as the default, for
; APP_ASSOCIATE to save again.
!macro BEEZIP_RESTORE_BACKUP EXT FILECLASS
  ReadRegStr $R0 SHCTX "Software\Classes\.${EXT}" ""
  StrCmp $R0 "${FILECLASS}" 0 +3
  ReadRegStr $R1 SHCTX "Software\Classes\.${EXT}" "${FILECLASS}_backup"
  WriteRegStr SHCTX "Software\Classes\.${EXT}" "" "$R1"
!macroend

; A running CLI (docs/M6.md §9.3): a `beezip mcp` server, which Claude Desktop starts, or a long
; CLI job holds bin\beezip.exe open, and Tauri's CheckIfAppIsRunning looks only at BeeZip.exe, so
; copying the new CLI would fail. A running exe can't be replaced or deleted, but it can be moved
; within its volume: it goes to %TEMP% (on the volume of %LOCALAPPDATA%, as M4 does with the
; menu's DLL), and an HKCU RunOnce value deletes it at the next sign-in. The process keeps
; running from there until its client restarts it.
; On install (COPY_BACK 1) an unlocked copy is put back at once, so an install cancelled later
; (CheckIfAppIsRunning's question comes after this hook) still leaves a working CLI; the
; installer then overwrites the copy. On uninstall (COPY_BACK 0) it just goes, so the install
; folder can too.
!macro BEEZIP_MOVE_LOCKED_CLI COPY_BACK
  IfFileExists "$INSTDIR\bin\beezip.exe" 0 beezip_cli_done_${COPY_BACK}
  ClearErrors
  FileOpen $R0 "$INSTDIR\bin\beezip.exe" a
  IfErrors beezip_cli_locked_${COPY_BACK}
  FileClose $R0
  Goto beezip_cli_done_${COPY_BACK}
  beezip_cli_locked_${COPY_BACK}:
  System::Call 'kernel32::GetTickCount() i .R0'
  StrCpy $R1 "$TEMP\BeeZip-cli-$R0.exe"
  ClearErrors
  Rename "$INSTDIR\bin\beezip.exe" "$R1"
  ; Not moved (another volume?): the copy fails as it did before.
  IfErrors beezip_cli_done_${COPY_BACK}
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\RunOnce" "BeeZip-cli-$R0" `cmd.exe /d /c del /f /q "$R1"`
  !if ${COPY_BACK} == 1
    CopyFiles /SILENT "$R1" "$INSTDIR\bin\beezip.exe"
  !endif
  beezip_cli_done_${COPY_BACK}:
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro BEEZIP_FOR_EACH_ASSOCIATION BEEZIP_RESTORE_BACKUP
  !insertmacro BEEZIP_MOVE_LOCKED_CLI 1
!macroend

!macro BEEZIP_CLEAN_UP EXT FILECLASS
  DeleteRegValue SHCTX "Software\Classes\.${EXT}" "${FILECLASS}_backup"
  ReadRegStr $R0 SHCTX "Software\Classes\.${EXT}" ""
  StrCmp $R0 "" +2 0
  StrCmp $R0 "${FILECLASS}" 0 +2
  DeleteRegValue SHCTX "Software\Classes\.${EXT}" ""
  DeleteRegKey /ifempty SHCTX "Software\Classes\.${EXT}"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  !insertmacro BEEZIP_FOR_EACH_ASSOCIATION BEEZIP_CLEAN_UP
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; The menu goes first, while beezip.exe is still there. A DLL Explorer holds is moved out of
  ; $INSTDIR, so the folder can go.
  nsExec::ExecToLog `"$INSTDIR\bin\beezip.exe" shell uninstall`
  Pop $0
  !insertmacro BEEZIP_MOVE_LOCKED_CLI 0
  !insertmacro BEEZIP_FOR_EACH_ASSOCIATION BEEZIP_KEEP_CURRENT
  System::Call 'Kernel32::SetEnvironmentVariable(t "BEEZIP_BIN", t "$INSTDIR\bin")'
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = $$env:BEEZIP_BIN.TrimEnd('\'); $$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $$true); if ($$k) { $$p = [string]$$k.GetValue('Path', '', 'DoNotExpandEnvironmentNames'); $$all = $$p.Split(';'); $$parts = @($$all | Where-Object { $$_.TrimEnd('\') -ne $$d }); if ($$parts.Count -ne $$all.Count) { $$k.SetValue('Path', ($$parts -join ';'), 'ExpandString'); [Environment]::SetEnvironmentVariable('BEEZIP_PATH_REFRESH', $$null, 'User') } }"`
  Pop $0
!macroend
