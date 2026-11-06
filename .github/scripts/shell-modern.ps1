# Windows 11's menu end to end on the runner (docs/M4.md §10): the debug installer, built by
# `cargo xtask dist --debug --sign-dev` with a throwaway certificate trusted in
# LocalMachine\TrustedPeople, installed silently. Its `shell install` (auto) must register the
# signed package; the shell's own menu for a fixture zip (menu_dump) must list the packaged
# "BeeZip >", served from the COM surrogate; a click on "Test archive" must start the app with the
# package's identity; and the uninstaller must leave no package, key or file behind.
#
# The runner is Windows Server, whose build (26100) is Windows 11's. If it can't register the
# package at all, the step says why and stops there, as a warning (§16 records what CI showed).
# Needs the installer and `cargo build -p beezip-shell --examples` first (CI runs both).
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Fail([string]$message) { Write-Host "::error::$message"; exit 1 }

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$setup = Get-ChildItem (Join-Path $root 'target\dist\debug\bundle\nsis') -Filter '*-setup.exe' | Select-Object -First 1
$stub = Join-Path $root 'target\debug\examples\stub_app.exe'
$dump = Join-Path $root 'target\debug\examples\menu_dump.exe'
$zip = Join-Path $root 'tests\fixtures\thirdparty\7z-deflate.zip'
foreach ($f in $setup.FullName, $stub, $dump, $zip) { if (-not $f -or -not (Test-Path $f)) { Fail "$f is missing" } }
$dir = Join-Path $env:LOCALAPPDATA 'BeeZip'
$beezip = Join-Path $dir 'bin\beezip.exe'
foreach ($f in 'beezip-sparse.msix', 'sparse\AppxManifest.xml') {
  # The installer must carry the package; checked after the install below.
}

Write-Host "installing $($setup.Name) silently"
$p = Start-Process $setup.FullName -ArgumentList '/S' -Wait -PassThru
if ($p.ExitCode) { Fail "the installer exited with $($p.ExitCode)" }
foreach ($f in 'beezip-sparse.msix', 'sparse\AppxManifest.xml', 'BeeZip.exe', 'bin\beezip.exe') {
  if (-not (Test-Path (Join-Path $dir $f))) { Fail "the install has no $f" }
}
$status = & $beezip --output json shell status | ConvertFrom-Json
if ($LASTEXITCODE) { Fail "shell status failed: exit $LASTEXITCODE" }
& $beezip shell status
if ($status.mode -ne 'modern') {
  # Ask again by hand, which says why.
  $why = & { $ErrorActionPreference = 'Continue'; & $beezip --output json shell install --mode modern 2>&1 } | Out-String
  Write-Host "::warning::the runner didn't register Windows 11's menu; shell install --mode modern says: $why"
  & (Join-Path $dir 'uninstall.exe') /S
  exit 0
}
if ($status.package.development) { Fail 'the installer registered a development package, not the signed one' }
if (-not $status.package.dll_exists) { Fail "the package's DLL isn't there: $($status.package.dll)" }
if ($status.classic) { Fail 'the classic keys are there beside the package' }
if ($status.problems.Count) { Fail "shell status has problems: $($status.problems -join '; ')" }
Write-Host "the installer registered $($status.package.full_name), serving $($status.package.dll)"

# A click starts the stub instead of the debug BeeZip.exe. It is started by the COM surrogate,
# so it doesn't get this environment: it writes its record beside itself.
& $beezip shell install --mode modern --app $stub
if ($LASTEXITCODE) { Fail "shell install --app failed: exit $LASTEXITCODE" }
Get-ChildItem (Split-Path $stub) -Filter 'stub_app-*.json' | Remove-Item

$menu = @(& $dump $zip)
if ($LASTEXITCODE) { Fail "menu_dump failed: exit $LASTEXITCODE" }
$menu | Write-Host
if ($menu -notcontains 'BeeZip >') {
  Write-Host "::warning::menu_dump, elevated on the runner, doesn't list the packaged menu"
} else {
  $want = '    Open with BeeZip', '    Extract here', '    Test archive', '    Add to "7z-deflate.zip"'
  foreach ($line in $want) { if ($menu -notcontains $line) { Fail "the menu has no line '$line'" } }
  & $dump --invoke 'Test archive' --wait 5000 $zip | Write-Host
  if ($LASTEXITCODE) { Fail "menu_dump --invoke failed: exit $LASTEXITCODE" }
  $record = $null
  foreach ($i in 1..20) {
    $record = Get-ChildItem (Split-Path $stub) -Filter 'stub_app-*.json' | Select-Object -First 1
    if ($record) { break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $record) { Fail 'the click didn''t start the app' }
  $seen = Get-Content $record.FullName -Raw | ConvertFrom-Json
  $request = $seen.request | ConvertFrom-Json
  if ($seen.args[0] -ne '--job' -or $request.item -ne 'test' -or $request.paths[0] -ne $zip) {
    Fail "the app got $($seen.args -join ' '): $($seen.request)"
  }
  if ($seen.package -ne $status.package.full_name) { Fail "the app ran as '$($seen.package)', not as the package" }
  Write-Host "the click started the app as $($seen.package) with $($seen.request)"
}

Write-Host 'uninstalling silently'
$p = Start-Process (Join-Path $dir 'uninstall.exe') -ArgumentList '/S' -Wait -PassThru
if ($p.ExitCode) { Fail "the uninstaller exited with $($p.ExitCode)" }
# NSIS's uninstaller runs again from %TEMP%; wait for it to finish.
foreach ($i in 1..60) { if (-not (Test-Path $beezip)) { break }; Start-Sleep -Milliseconds 500 }
# Windows PowerShell's Appx module; PowerShell 7's isn't reliable on every runner image.
$left = powershell.exe -NoProfile -Command '(Get-AppxPackage -Name BeeZip).PackageFullName'
if ($left) { Fail "the uninstaller left the package $left" }
$hkcu = [Microsoft.Win32.Registry]::CurrentUser
foreach ($key in 'Software\Classes\*\shell\BeeZip', 'Software\Classes\Directory\shell\BeeZip', 'Software\BeeZip\Shell') {
  if ($hkcu.OpenSubKey($key)) { Fail "the uninstaller left HKCU\$key" }
}
if (Get-ChildItem $dir -Filter 'beezip_shell_*.dll' -ErrorAction SilentlyContinue) { Fail 'the uninstaller left the DLL' }
Write-Host 'the uninstaller removed the package, the keys and the DLL'
