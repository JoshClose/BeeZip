# The end-to-end smoke test on the Windows runner (docs/M6.md §10): tauri-driver 2.1.0 and the
# msedgedriver that matches the runner's WebView2, then tests/e2e/smoke.mjs against the BeeZip.exe
# that `cargo xtask dist --debug` built, with a scratch config and WebView2 profile. Stops only
# the processes it started, by their ids. On a failure it says what msedgedriver did, and whether
# BeeZip's WebView2 opens a DevTools port on this machine at all.
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
# tauri-driver starts the native driver with its port only; this wrapper adds a verbose log.
$log = Join-Path $work 'msedgedriver.log'
$wrapper = Join-Path $work 'edgedriver\msedgedriver-logged.cmd'
Set-Content $wrapper "@`"$native`" %* --verbose `"--log-path=$log`"" -Encoding ascii
$driver = (Get-Command tauri-driver -ErrorAction SilentlyContinue).Source
if (-not $driver) { Fail 'tauri-driver is missing (cargo install --locked tauri-driver --version 2.1.0)' }

# The app's surroundings: a config that never looks for updates, and a profile of its own.
Set-Content (Join-Path $work 'config.toml') "[updates]`ncheck = false`n" -Encoding utf8NoBOM
$env:BEEZIP_CONFIG = Join-Path $work 'config.toml'
$env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $work 'webview2'
$port = 4444
$env:WD_URL = "http://127.0.0.1:$port"

# Every process below `id`, deepest first.
function Descendants([int]$id) {
  foreach ($c in @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $id" -ErrorAction SilentlyContinue)) {
    Descendants $c.ProcessId
    $c
  }
}

$td = Start-Process $driver -ArgumentList "--port $port --native-port $($port + 1) --native-driver `"$wrapper`"" -PassThru -NoNewWindow `
  -RedirectStandardOutput (Join-Path $work 'tauri-driver.out') -RedirectStandardError (Join-Path $work 'tauri-driver.err')
try {
  $deadline = (Get-Date).AddSeconds(30)
  while (-not (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { Fail 'tauri-driver never listened' }
    Start-Sleep -Milliseconds 200
  }
  node (Join-Path $root 'tests\e2e\smoke.mjs') $exe $archive tree
  $code = $LASTEXITCODE
  if ($code) {
    Write-Host 'processes under tauri-driver:'
    Descendants $td.Id | ForEach-Object { Write-Host "  $($_.ProcessId) $($_.Name): $($_.CommandLine)" }
  }
} finally {
  foreach ($p in @(Descendants $td.Id)) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
  Stop-Process -Id $td.Id -Force -ErrorAction SilentlyContinue
  Write-Host 'tauri-driver said:'
  Get-Content (Join-Path $work 'tauri-driver.err'), (Join-Path $work 'tauri-driver.out') -ErrorAction SilentlyContinue | Select-Object -Last 20
}
if ($code) {
  Write-Host 'msedgedriver said (last 60 lines):'
  Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 60
  # BeeZip on its own, with a DevTools port: does its WebView2 come up here at all?
  $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = '--remote-debugging-port=9333'
  $env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $work 'webview2-direct'
  $app = Start-Process $exe -PassThru -RedirectStandardError (Join-Path $work 'app.err') -RedirectStandardOutput (Join-Path $work 'app.out')
  Start-Sleep -Seconds 20
  try { $pages = (Invoke-WebRequest http://127.0.0.1:9333/json -UseBasicParsing -TimeoutSec 5).Content } catch { $pages = "no answer: $_" }
  Write-Host "started on its own, BeeZip is $(if ($app.HasExited) { "gone (exit $($app.ExitCode))" } else { 'running' }); DevTools: $pages"
  Get-Content (Join-Path $work 'app.err'), (Join-Path $work 'app.out') -ErrorAction SilentlyContinue | Select-Object -Last 20
  foreach ($p in @(Descendants $app.Id)) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
  Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue
  Fail "the smoke test failed: exit $code"
}
