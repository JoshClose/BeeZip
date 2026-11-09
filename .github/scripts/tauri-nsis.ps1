# Puts the NSIS that `tauri build` uses where Tauri looks for it (%LOCALAPPDATA%\tauri\NSIS),
# fetched with retries and checked, so the build doesn't depend on Tauri's own single download
# from GitHub's release URLs, which answered 504 for an hour while PR 5's CI ran
# (docs/M6.md §16, PR 5). The URLs, hashes and layout are tauri-bundler 2.10.4's (Tauri CLI
# 2.12.4; src/bundle/windows/nsis/mod.rs): when Tauri moves on, it finds this folder outdated
# and downloads its own, so update these with it.
$ErrorActionPreference = 'Stop'
function Fail([string]$message) { Write-Host "::error::$message"; exit 1 }

$tools = Join-Path $env:LOCALAPPDATA 'tauri'
$nsis = Join-Path $tools 'NSIS'
if (Test-Path (Join-Path $nsis 'Plugins\x86-unicode\additional\nsis_tauri_utils.dll')) {
  Write-Host "NSIS is already at $nsis"
  exit 0
}
$work = Join-Path ([IO.Path]::GetTempPath()) "tauri-nsis-$PID"
New-Item -ItemType Directory -Force $work, $tools | Out-Null

function Fetch([string]$url, [string]$sha1, [string]$out) {
  Invoke-WebRequest -Uri $url -OutFile $out -MaximumRetryCount 6 -RetryIntervalSec 20
  $hash = (Get-FileHash -Algorithm SHA1 $out).Hash
  if ($hash -ne $sha1) { Fail "$url has SHA-1 $hash, not $sha1" }
}

$zip = Join-Path $work 'nsis-3.13.zip'
Fetch 'https://github.com/tauri-apps/binary-releases/releases/download/nsis-3.13/nsis-3.13.zip' 'DB14F8AF2EA346B786C6AE19343F61AAF5E09B8E' $zip
$dll = Join-Path $work 'nsis_tauri_utils.dll'
Fetch 'https://github.com/tauri-apps/nsis-tauri-utils/releases/download/nsis_tauri_utils-v0.5.3/nsis_tauri_utils.dll' '75197FEE3C6A814FE035788D1C34EAD39349B860' $dll

if (Test-Path $nsis) { Remove-Item -Recurse -Force $nsis }
Expand-Archive -LiteralPath $zip -DestinationPath $tools -Force
Rename-Item (Join-Path $tools 'nsis-3.13') 'NSIS'
$additional = Join-Path $nsis 'Plugins\x86-unicode\additional'
New-Item -ItemType Directory -Force $additional | Out-Null
Copy-Item $dll (Join-Path $additional 'nsis_tauri_utils.dll')
Remove-Item -Recurse -Force $work
Write-Host "NSIS 3.13 and nsis_tauri_utils 0.5.3 are at $nsis"
