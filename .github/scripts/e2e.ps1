# The end-to-end smoke test on the Windows runner (docs/M6.md §10): tauri-driver 2.1.0 and the
# msedgedriver that matches the runner's WebView2, then tests/e2e/smoke.mjs against the BeeZip.exe
# that `cargo xtask dist --debug` built, with a scratch config and WebView2 profile. Stops only
# the processes it started, by their ids.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Fail([string]$message) { Write-Host "::error::$message"; exit 1 }

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$exe = Join-Path $root 'target\dist\debug\BeeZip.exe'
$archive = Join-Path $root 'tests\fixtures\thirdparty\7z-deflate.zip'
foreach ($f in $exe, $archive) { if (-not (Test-Path $f)) { Fail "$f is missing" } }
$work = Join-Path ([IO.Path]::GetTempPath()) "beezip-e2e-$PID"
New-Item -ItemType Directory -Force $work | Out-Null

# The WebView2 runtime's version, and the msedgedriver built for it.
$client = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
$version = (Get-ItemProperty $client -Name pv).pv
if (-not $version) { Fail "no WebView2 runtime version under $client" }
Write-Host "WebView2 $version"
$zip = Join-Path $work 'edgedriver_win64.zip'
Invoke-WebRequest "https://msedgedriver.microsoft.com/$version/edgedriver_win64.zip" -OutFile $zip
Expand-Archive $zip (Join-Path $work 'edgedriver')
$native = Join-Path $work 'edgedriver\msedgedriver.exe'
$driver = (Get-Command tauri-driver -ErrorAction SilentlyContinue).Source
if (-not $driver) { Fail 'tauri-driver is missing (cargo install --locked tauri-driver --version 2.1.0)' }

# The app's surroundings: a config that never looks for updates, its own WebView2 profile.
Set-Content (Join-Path $work 'config.toml') "[updates]`ncheck = false`n" -Encoding utf8NoBOM
$env:BEEZIP_CONFIG = Join-Path $work 'config.toml'
$env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $work 'webview2'
$port = 4444
$env:WD_URL = "http://127.0.0.1:$port"

$td = Start-Process $driver -ArgumentList "--port $port --native-port $($port + 1) --native-driver `"$native`"" -PassThru -NoNewWindow `
  -RedirectStandardOutput (Join-Path $work 'tauri-driver.out') -RedirectStandardError (Join-Path $work 'tauri-driver.err')
try {
  $deadline = (Get-Date).AddSeconds(30)
  while (-not (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { Fail 'tauri-driver never listened' }
    Start-Sleep -Milliseconds 200
  }
  node (Join-Path $root 'tests\e2e\smoke.mjs') $exe $archive tree
  $code = $LASTEXITCODE
} finally {
  # msedgedriver and anything it left are tauri-driver's children.
  $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $($td.Id)" -ErrorAction SilentlyContinue
  foreach ($c in $children) {
    Get-CimInstance Win32_Process -Filter "ParentProcessId = $($c.ProcessId)" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Stop-Process -Id $c.ProcessId -Force -ErrorAction SilentlyContinue
  }
  Stop-Process -Id $td.Id -Force -ErrorAction SilentlyContinue
  Write-Host 'tauri-driver said:'
  Get-Content (Join-Path $work 'tauri-driver.err'), (Join-Path $work 'tauri-driver.out') -ErrorAction SilentlyContinue | Select-Object -Last 20
}
if ($code) { Fail "the smoke test failed: exit $code" }
