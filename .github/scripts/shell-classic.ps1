# Explorer's classic menu end to end on the runner (docs/M4.md §10): `beezip shell install` with
# the debug DLL and the stub app, the shell's own menu for a fixture zip (menu_dump, which builds
# it as Explorer does), a click on "Test archive", and `beezip shell uninstall` leaving nothing.
# Needs `cargo build -p beezip-cli -p beezip-shell --examples` first (CI runs it).
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)   # menu_dump writes UTF-8
function Fail([string]$message) { Write-Host "::error::$message"; exit 1 }

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$debug = Join-Path $root 'target\debug'
$beezip = Join-Path $debug 'beezip.exe'
$dll = Join-Path $debug 'beezip_shell.dll'
# `cargo test` builds the DLL into deps\ without copying it up, and a later build may find it fresh.
if (-not (Test-Path $dll)) { $dll = Join-Path $debug 'deps\beezip_shell.dll' }
$stub = Join-Path $debug 'examples\stub_app.exe'
$dump = Join-Path $debug 'examples\menu_dump.exe'
$zip = Join-Path $root 'tests\fixtures\thirdparty\7z-deflate.zip'
foreach ($f in $beezip, $dll, $stub, $dump, $zip) { if (-not (Test-Path $f)) { Fail "$f is missing" } }
$env:BEEZIP_STUB_OUT = Join-Path $env:RUNNER_TEMP 'beezip-stub'
New-Item -ItemType Directory -Force $env:BEEZIP_STUB_OUT | Out-Null

& $beezip shell install --mode classic --dll $dll --app $stub
if ($LASTEXITCODE) { Fail "shell install failed: exit $LASTEXITCODE" }
& $beezip shell status
if ($LASTEXITCODE) { Fail "shell status failed: exit $LASTEXITCODE" }

# COM ignores per-user classes in an elevated process (checked on Windows 10), and the runner is
# an administrator. Explorer runs unelevated, so there the HKCU class is used. Here a copy of the
# class key goes into HKLM for menu_dump; the verbs it finds are still the ones in HKCU.
$class = 'Software\Classes\CLSID\{B788B651-F40D-446D-A601-2D23F9E0C37B}'
$copied = $false
try {
  $menu = @(& $dump $zip)
  if ($LASTEXITCODE) { Fail "menu_dump failed: exit $LASTEXITCODE" }
  if ($menu -notcontains 'BeeZip >') {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
    if (-not $admin) { $menu | Write-Host; Fail 'the menu has no "BeeZip >"' }
    Write-Host 'Elevated: the class goes into HKLM for menu_dump, the verbs stay in HKCU.'
    reg.exe copy "HKCU\$class" "HKLM\$class" /s /f | Out-Null
    if ($LASTEXITCODE) { Fail 'copying the class to HKLM failed' }
    $copied = $true
    $menu = @(& $dump $zip)
  }
  $menu | Write-Host
  $want = 'BeeZip >', '    Open with BeeZip', '    Extract here', '    Extract to "7z-deflate\"', '    Test archive',
    '    -----', '    Add to "7z-deflate.zip"', '    Add to "7z-deflate.7z"'
  foreach ($line in $want) { if ($menu -notcontains $line) { Fail "the menu has no line '$line'" } }
  if (-not ($menu -like '    Compress to*')) { Fail 'the menu has no "Compress to"' }

  & $dump --invoke 'Test archive' --wait 5000 $zip | Write-Host
  if ($LASTEXITCODE) { Fail "menu_dump --invoke failed: exit $LASTEXITCODE" }
  $record = Get-ChildItem $env:BEEZIP_STUB_OUT -Filter 'stub_app-*.json' | Select-Object -First 1
  if (-not $record) { Fail 'the click didn''t start the app' }
  $seen = Get-Content $record.FullName -Raw | ConvertFrom-Json
  if ($seen.args[0] -ne '--job') { Fail "the app got $($seen.args -join ' ')" }
  $request = $seen.request | ConvertFrom-Json
  if ($request.item -ne 'test' -or $request.paths[0] -ne $zip) { Fail "the request was $($seen.request)" }
  Write-Host "the click started the app with $($seen.args -join ' '): $($seen.request)"
} finally {
  if ($copied) { reg.exe delete "HKLM\$class" /f | Out-Null }
}

& $beezip shell uninstall
if ($LASTEXITCODE) { Fail "shell uninstall failed: exit $LASTEXITCODE" }
$hkcu = [Microsoft.Win32.Registry]::CurrentUser
foreach ($key in 'Software\Classes\*\shell\BeeZip', 'Software\Classes\Directory\shell\BeeZip', $class, 'Software\BeeZip\Shell') {
  if ($hkcu.OpenSubKey($key)) { Fail "shell uninstall left HKCU\$key" }
}
Write-Host 'shell uninstall left no keys'
