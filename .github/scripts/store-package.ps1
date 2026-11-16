# The Microsoft Store package (docs/M12.md §2, §5), beside the portable zip `xtask dist` made with
# it:
# - it's named BeeZip_<V>_x64.msix, unsigned (Microsoft signs it), with Partner Center's identity
#   and version <V>.0 in its manifest;
# - its programs and documents are the portable zip's, byte for byte, so a signed build's
#   programs are signed in it too.
# With -Register (CI), its layout is also registered under Developer Mode, which the step turns
# on:
# - the `beezip` alias runs;
# - the shell's own menu for a fixture zip lists "BeeZip >", served from the package;
# - a click starts the BeeZip.exe beside the package's DLL, with the package's identity. A copy
#   of the layout is registered, with the stub as its BeeZip.exe.
# Then the package is removed, and its alias with it.
#
# Usage: store-package.ps1 <BeeZip_V_x64.msix> <BeeZip_V_x64-portable.zip> [-Register]
param(
  [Parameter(Mandatory, Position = 0)][string]$Msix,
  [Parameter(Mandatory, Position = 1)][string]$Zip,
  [switch]$Register
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Fail([string]$message) { Write-Host "::error::$message"; exit 1 }
Add-Type -AssemblyName System.IO.Compression.FileSystem

# beezip_commands::shell::store
$name = 'CloseConsultingInc.BeeZip'
$publisher = 'CN=B81ECA8F-95E1-4C2B-B747-FE4DA97C8BFC'
$family = 'CloseConsultingInc.BeeZip_x5m1y1n6e4ce4'

$msixFile = Get-Item -LiteralPath $Msix
if ($msixFile.Name -notmatch '^BeeZip_(\d+\.\d+\.\d+)_x64\.msix$') { Fail "$($msixFile.Name) isn't named BeeZip_<version>_x64.msix" }
$version = $Matches[1]

# The SHA-256 of each file in a zip, by its path with `/`.
function Hashes([string]$path) {
  $out = @{}
  $archive = [IO.Compression.ZipFile]::OpenRead($path)
  try {
    foreach ($e in $archive.Entries | Where-Object { $_.Length -or -not $_.FullName.EndsWith('/') }) {
      $s = $e.Open()
      try { $out[[Uri]::UnescapeDataString($e.FullName).Replace('\', '/')] = (Get-FileHash -InputStream $s -Algorithm SHA256).Hash }
      finally { $s.Dispose() }
    }
  } finally { $archive.Dispose() }
  $out
}
$inMsix = Hashes $msixFile.FullName
$inZip = Hashes (Get-Item -LiteralPath $Zip).FullName

if ($inMsix.ContainsKey('AppxSignature.p7x')) { Fail 'the package is signed: Microsoft signs it, so it must not be' }
$archive = [IO.Compression.ZipFile]::OpenRead($msixFile.FullName)
try {
  $reader = [IO.StreamReader]::new($archive.GetEntry('AppxManifest.xml').Open())
  [xml]$manifest = $reader.ReadToEnd()
  $reader.Dispose()
} finally { $archive.Dispose() }
$identity = $manifest.Package.Identity
if ($identity.Name -ne $name) { Fail "the package is named $($identity.Name), not $name" }
if ($identity.Publisher -ne $publisher) { Fail "the package's publisher is $($identity.Publisher), not $publisher" }
if ($identity.Version -ne "$version.0") { Fail "the package's version is $($identity.Version), not $version.0" }
Write-Host "the package is $($identity.Name) $($identity.Version), published by $($identity.Publisher), unsigned"

$programs = 'BeeZip.exe', 'bin/beezip.exe', "beezip_shell_$version.dll", 'LICENSE-MIT', 'LICENSE-APACHE', 'THIRD_PARTY_NOTICES.md'
foreach ($f in $programs) {
  if (-not $inMsix.ContainsKey($f)) { Fail "the package holds no $f" }
  if ($inMsix[$f] -ne $inZip[$f]) { Fail "the package's $f isn't the portable zip's" }
}
foreach ($f in $inMsix.Keys | Sort-Object) {
  $known = $f -in $programs -or $f -like 'Assets/*' -or $f -in 'AppxManifest.xml', 'AppxBlockMap.xml', '[Content_Types].xml', 'resources.pri'
  if (-not $known) { Fail "the package holds $f, which it shouldn't" }
}
Write-Host "its programs and documents are the portable zip's: $($programs -join ', ')"

if (-not $Register) { exit 0 }

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$layout = Join-Path $msixFile.DirectoryName 'layout'
$dump = Join-Path $root 'target\debug\examples\menu_dump.exe'
$stub = Join-Path $root 'target\debug\examples\stub_app.exe'
$fixture = Join-Path $root 'tests\fixtures\thirdparty\7z-deflate.zip'
foreach ($f in "$layout\AppxManifest.xml", $dump, $stub, $fixture) { if (-not (Test-Path $f)) { Fail "$f is missing" } }

# Windows PowerShell's Appx module, without PowerShell 7's module path (shell-modern.ps1 says why).
function Appx([string]$command) {
  $saved = $env:PSModulePath; $env:PSModulePath = $null
  try { powershell.exe -NoProfile -Command "`$ErrorActionPreference = 'Stop'; $command" }
  finally { $env:PSModulePath = $saved }
  if ($LASTEXITCODE) { Fail "Windows PowerShell failed: $command" }
}

$unlock = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
if ((Get-ItemProperty $unlock -ErrorAction SilentlyContinue).AllowDevelopmentWithoutDevLicense -ne 1) {
  New-Item $unlock -Force | Out-Null
  Set-ItemProperty $unlock AllowDevelopmentWithoutDevLicense 1 -Type DWord
  Write-Host 'Developer Mode turned on'
}

# A copy of the layout, with the stub as BeeZip.exe: a click records how it was started.
$copy = Join-Path ([IO.Path]::GetTempPath()) ("beezip-store-" + [Guid]::NewGuid().ToString('N'))
Copy-Item -LiteralPath $layout -Destination $copy -Recurse
Copy-Item -LiteralPath $stub -Destination (Join-Path $copy 'BeeZip.exe') -Force
try {
  Appx "Add-AppxPackage -Register '$copy\AppxManifest.xml'"
  $registered = Appx "(Get-AppxPackage -Name $name).PackageFamilyName"
  if ("$registered".Trim() -ne $family) { Fail "registered as '$registered', not $family" }
  $full = "$(Appx "(Get-AppxPackage -Name $name).PackageFullName")".Trim()
  Write-Host "registered $full"

  $alias = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\beezip.exe'
  if (-not (Test-Path $alias)) { Fail "no alias at $alias" }
  $out = & $alias --version
  if ($LASTEXITCODE) { Fail "the alias failed: exit $LASTEXITCODE" }
  if ("$out" -notmatch [regex]::Escape($version)) { Fail "the alias said '$out', not $version" }
  Write-Host "beezip --version through the alias: $out"

  $menu = @(& $dump $fixture)
  if ($LASTEXITCODE) { Fail "menu_dump failed: exit $LASTEXITCODE" }
  if ($menu -notcontains 'BeeZip >') {
    $menu | Write-Host
    Write-Host "::warning::menu_dump, elevated on the runner, doesn't list the package's menu"
  } else {
    foreach ($line in '    Extract here', '    Test archive') { if ($menu -notcontains $line) { Fail "the menu has no line '$line'" } }
    & $dump --invoke 'Test archive' --wait 5000 $fixture | Write-Host
    if ($LASTEXITCODE) { Fail "menu_dump --invoke failed: exit $LASTEXITCODE" }
    $record = $null
    foreach ($i in 1..20) {
      $record = Get-ChildItem $copy -Filter 'stub_app-*.json' | Select-Object -First 1
      if ($record) { break }
      Start-Sleep -Milliseconds 500
    }
    if (-not $record) { Fail 'the click didn''t start the BeeZip.exe beside the DLL' }
    $seen = Get-Content $record.FullName -Raw | ConvertFrom-Json
    $request = $seen.request | ConvertFrom-Json
    if ($seen.args[0] -ne '--job' -or $request.item -ne 'test' -or $request.paths[0] -ne $fixture) {
      Fail "the app got $($seen.args -join ' '): $($seen.request)"
    }
    if ($seen.package -ne $full) { Fail "the app ran as '$($seen.package)', not as the package" }
    Write-Host "the click started the package's own BeeZip.exe as $($seen.package)"
  }
} finally {
  Appx "Get-AppxPackage -Name $name | Remove-AppxPackage"
  Remove-Item -LiteralPath $copy -Recurse -Force -ErrorAction SilentlyContinue
}
if (Test-Path (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\beezip.exe')) { Fail 'removing the package left its alias' }
Write-Host 'the package and its alias are gone'
