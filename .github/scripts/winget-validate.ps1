# `winget validate` on the manifest `cargo xtask winget --local` wrote (docs/M6.md §9.6, §10).
# windows-latest (Windows Server 2025) comes with winget. If it doesn't, or its winget is older
# than the manifests' schema (1.12), winget 1.29.380 is installed from its GitHub release,
# checked against the SHA-256 GitHub reports for each file.
#
# Usage: winget-validate.ps1 <the folder holding the three manifest files>
param([Parameter(Mandatory)][string]$Manifest)
$ErrorActionPreference = 'Stop'
function Fail([string]$message) { Write-Host "::error::$message"; exit 1 }

function Get-WingetVersion {
  try {
    $text = & winget --version 2>$null
    if ($LASTEXITCODE -eq 0 -and "$text" -match '^v?(\d+\.\d+(\.\d+)?)') { return [version]$Matches[1] }
  } catch {}
  $null
}

$have = Get-WingetVersion
if (-not $have -or $have -lt [version]'1.12') {
  Write-Host "winget $have can't read schema 1.12: installing winget 1.29.380"
  $base = 'https://github.com/microsoft/winget-cli/releases/download/v1.29.380'
  $files = [ordered]@{
    'DesktopAppInstaller_Dependencies.zip'                   = 'BA875AFE9D190F61218985AC0292A99D1DB710BF93E13C68944CA9D89F0D82D1'
    'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' = '65DEA9C01CE08EE7B763366B27C0E651F97DB857C11CA9B9C301826C10092F2E'
  }
  $dir = Join-Path $env:RUNNER_TEMP 'winget'
  New-Item -ItemType Directory -Force $dir | Out-Null
  foreach ($name in $files.Keys) {
    $path = Join-Path $dir $name
    # GitHub's downloads time out now and then (a 504 seen on CI).
    Invoke-WebRequest -Uri "$base/$name" -OutFile $path -MaximumRetryCount 4 -RetryIntervalSec 15
    $hash = (Get-FileHash -Algorithm SHA256 $path).Hash
    if ($hash -ne $files[$name]) { Fail "$name's SHA-256 is $hash" }
  }
  Expand-Archive -LiteralPath (Join-Path $dir 'DesktopAppInstaller_Dependencies.zip') -DestinationPath (Join-Path $dir 'deps')
  $packages = @(Get-ChildItem (Join-Path $dir 'deps') -Recurse -File | Where-Object { $_.Directory.Name -eq 'x64' -and $_.Extension -in '.appx', '.msix' }) +
    @(Get-Item (Join-Path $dir 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'))
  # Windows PowerShell's Appx module, without PowerShell 7's module path (as shell-modern.ps1).
  $saved = $env:PSModulePath; $env:PSModulePath = $null
  try {
    foreach ($p in $packages) {
      Write-Host "Add-AppxPackage $($p.Name)"
      powershell.exe -NoProfile -NonInteractive -Command "Add-AppxPackage -Path '$($p.FullName)'"
      if ($LASTEXITCODE) { Fail "Add-AppxPackage $($p.Name) failed" }
    }
  } finally { $env:PSModulePath = $saved }
  $env:PATH = "$env:LOCALAPPDATA\Microsoft\WindowsApps;$env:PATH"
  $have = Get-WingetVersion
  if (-not $have) { Fail 'winget still doesn''t run after installing it' }
}
Write-Host "winget $have"

& winget validate --manifest $Manifest --disable-interactivity
if ($LASTEXITCODE) { Fail "winget validate failed on $Manifest (exit $LASTEXITCODE)" }
