# A running CLI during a reinstall and an uninstall (docs/M6.md §9.3, §10): a `beezip mcp` server
# holds bin\beezip.exe open, as Claude Desktop's does. hooks.nsh must move it to %TEMP% (with a
# RunOnce value that deletes it at the next sign-in), so a silent reinstall over the top still
# installs the new CLI, and a silent uninstall still removes the install folder; the server keeps
# running throughout. Needs the debug installer (`cargo xtask dist --debug`). Stops only the
# processes it started, by their ids.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Fail([string]$message) { Write-Host "::error::$message"; exit 1 }

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$setup = Get-ChildItem (Join-Path $root 'target\dist\debug\bundle\nsis') -Filter '*-setup.exe' | Select-Object -First 1
if (-not $setup) { Fail 'no installer under target\dist\debug\bundle\nsis' }
$dir = Join-Path $env:LOCALAPPDATA 'BeeZip'
$cli = Join-Path $dir 'bin\beezip.exe'
$runOnce = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
# Apps & features' entry, and Tauri's own key, named after bundle.publisher (docs/M6.md §9.3, §9.6):
# winget matches the install to its package by this Publisher.
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\BeeZip'
$publisher = (Get-Content -Raw (Join-Path $root 'packaging\windows\tauri.dist.json') | ConvertFrom-Json).bundle.publisher
$tauriKey = "HKCU:\Software\$publisher"
$work = Join-Path ([IO.Path]::GetTempPath()) "beezip-locked-cli-$PID"
New-Item -ItemType Directory -Force $work | Out-Null
$servers = [Collections.Generic.List[Diagnostics.Process]]::new()

function Install([string]$what, [string]$exe) {
  Write-Host $what
  $p = Start-Process $exe -ArgumentList '/S' -Wait -PassThru
  if ($p.ExitCode) { Fail "$what`: exit $($p.ExitCode)" }
}

# `beezip mcp` from the installed CLI, its stdin held open so it waits for a client.
function Start-Server {
  # .Arguments rather than .ArgumentList, which Windows PowerShell 5.1 lacks (the VM runs this too).
  $info = New-Object Diagnostics.ProcessStartInfo $cli, "mcp --root `"$work`""
  $info.RedirectStandardInput = $true
  $info.RedirectStandardOutput = $true
  $info.UseShellExecute = $false
  $info.Environment['BEEZIP_CONFIG'] = Join-Path $work 'config.toml'
  $p = [Diagnostics.Process]::Start($info)
  $servers.Add($p)
  Start-Sleep -Seconds 1
  if ($p.HasExited) { Fail "beezip mcp exited at once: $($p.ExitCode)" }
  Write-Host "beezip mcp runs as process $($p.Id), holding $cli"
  $p
}

# The RunOnce values hooks.nsh wrote, and the files they delete.
function Moved {
  $key = Get-Item $runOnce -ErrorAction SilentlyContinue
  if (-not $key) { return @() }
  @($key.GetValueNames() | Where-Object { $_ -like 'BeeZip-cli-*' } | ForEach-Object {
      $command = $key.GetValue($_)
      if ($command -notmatch '"([^"]+)"') { Fail "RunOnce $_ deletes nothing: $command" }
      [pscustomobject]@{ Name = $_; Command = $command; File = $Matches[1] }
    })
}

try {
  if (Moved) { Fail 'RunOnce already has BeeZip-cli values' }
  Install "installing $($setup.Name) silently" $setup.FullName
  $entry = Get-ItemProperty $uninstallKey -ErrorAction SilentlyContinue
  if (-not $entry) { Fail "no Apps & features entry at $uninstallKey" }
  if ($entry.Publisher -cne $publisher) { Fail "Apps & features names the publisher '$($entry.Publisher)', not '$publisher'" }
  # Compared by what's in it: NSIS may write a folder in its 8.3 form.
  $kept = (Get-ItemProperty "$tauriKey\BeeZip" -ErrorAction SilentlyContinue).'(default)'
  if (-not $kept -or -not (Test-Path (Join-Path $kept 'bin\beezip.exe'))) { Fail "$tauriKey\BeeZip holds '$kept', not the install folder $dir" }
  Write-Host "Apps & features: BeeZip by $($entry.Publisher); the install folder is kept in $tauriKey\BeeZip"
  $first = Start-Server

  Install 'reinstalling over it while beezip mcp holds the CLI' $setup.FullName
  if ($first.HasExited) { Fail 'the reinstall stopped the running server' }
  $moved = @(Moved)
  if ($moved.Count -ne 1) { Fail "expected one RunOnce value for the moved CLI, found $($moved.Count)" }
  $m = $moved[0]
  # NSIS's $TEMP may be the 8.3 form of the folder (C:\Users\RUNNER~1\…), so look for the file
  # by its name in %TEMP% rather than compare paths.
  if (-not (Test-Path $m.File)) { Fail "the moved CLI isn't at $($m.File)" }
  if (-not (Test-Path (Join-Path ([IO.Path]::GetTempPath()) (Split-Path $m.File -Leaf)))) { Fail "the CLI was moved to $($m.File), not into %TEMP%" }
  if ($m.Command -notlike 'cmd.exe /d /c del /f /q "*"') { Fail "RunOnce $($m.Name) is $($m.Command)" }
  Write-Host "the running CLI went to $($m.File), deleted at the next sign-in by RunOnce $($m.Name)"
  # The installed CLI is a new file, not the one running: it can be opened for writing.
  try { [IO.File]::Open($cli, 'Open', 'ReadWrite', 'None').Dispose() } catch { Fail "the reinstalled CLI is still locked: $_" }
  $version = & $cli version
  if ($LASTEXITCODE) { Fail "the reinstalled CLI doesn't run: exit $LASTEXITCODE" }
  Write-Host "the reinstalled CLI runs: $version"

  # And an uninstall while a server holds the new CLI.
  $second = Start-Server
  Write-Host 'uninstalling silently while beezip mcp holds the CLI'
  $p = Start-Process (Join-Path $dir 'uninstall.exe') -ArgumentList '/S' -Wait -PassThru
  if ($p.ExitCode) { Fail "the uninstaller exited with $($p.ExitCode)" }
  # NSIS's uninstaller runs again from %TEMP%; wait for it to finish.
  foreach ($i in 1..60) { if (-not (Test-Path $dir)) { break }; Start-Sleep -Milliseconds 500 }
  if (Test-Path $dir) { Fail "the uninstaller left $dir`: $((Get-ChildItem -Recurse $dir).FullName -join ', ')" }
  if ($second.HasExited -or $first.HasExited) { Fail 'the uninstall stopped a running server' }
  if (@(Moved).Count -ne 2) { Fail "expected a second RunOnce value, for the CLI the uninstall moved: $(@(Moved).Name -join ', ')" }
  # Tauri's own key stays unless "Delete the application data" was ticked, which /S doesn't.
  if (Test-Path $uninstallKey) { Fail "the uninstaller left $uninstallKey" }
  Write-Host 'the uninstaller removed the install folder; both servers still run from %TEMP%'
} finally {
  foreach ($p in $servers) { if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit(5000) | Out-Null } }
  foreach ($m in Moved) {
    Remove-ItemProperty $runOnce -Name $m.Name
    if (Test-Path $m.File) { [IO.File]::Delete($m.File) }
  }
  if (Test-Path (Join-Path $dir 'uninstall.exe')) { Start-Process (Join-Path $dir 'uninstall.exe') -ArgumentList '/S' -Wait }
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
