; Installer hooks for Tauri's NSIS template (docs/M3.md §5.5): put $INSTDIR\bin, which holds
; beezip.exe, on the user's PATH, and take it off again on uninstall.
;
; PowerShell edits PATH rather than NSIS, whose strings hold 1 024 characters in its default
; build: a longer PATH would be cut. The script reads the value unexpanded (so %USERPROFILE%
; and the like survive), adds or removes the folder once, writes it back as REG_EXPAND_SZ, and
; then deletes a variable that doesn't exist, which makes .NET broadcast WM_SETTINGCHANGE so new
; shells see the change.
;
; The folder reaches the script through the BEEZIP_BIN environment variable, so no path needs
; quoting. In NSIS strings `$$` is a literal `$`; the script has no double quotes.

!macro NSIS_HOOK_POSTINSTALL
  System::Call 'Kernel32::SetEnvironmentVariable(t "BEEZIP_BIN", t "$INSTDIR\bin")'
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = $$env:BEEZIP_BIN.TrimEnd('\'); $$k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment'); $$p = [string]$$k.GetValue('Path', '', 'DoNotExpandEnvironmentNames'); $$parts = @($$p.Split(';') | Where-Object { $$_ }); if (-not ($$parts | Where-Object { $$_.TrimEnd('\') -eq $$d })) { $$parts += $$d; $$k.SetValue('Path', ($$parts -join ';'), 'ExpandString'); [Environment]::SetEnvironmentVariable('BEEZIP_PATH_REFRESH', $$null, 'User') }"`
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  System::Call 'Kernel32::SetEnvironmentVariable(t "BEEZIP_BIN", t "$INSTDIR\bin")'
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = $$env:BEEZIP_BIN.TrimEnd('\'); $$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $$true); if ($$k) { $$p = [string]$$k.GetValue('Path', '', 'DoNotExpandEnvironmentNames'); $$parts = @($$p.Split(';') | Where-Object { $$_ -and ($$_.TrimEnd('\') -ne $$d) }); $$k.SetValue('Path', ($$parts -join ';'), 'ExpandString'); [Environment]::SetEnvironmentVariable('BEEZIP_PATH_REFRESH', $$null, 'User') }"`
  Pop $0
!macroend
