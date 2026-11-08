# Every program in a signed installer carries a signature (docs/M6.md §9.2): the setup, and in
# it (7-Zip opens NSIS installers) BeeZip.exe, bin\beezip.exe, the menu's DLL, and NSIS's plugins
# in $PLUGINSDIR, nsExec.dll included, which Tauri 2.12 leaves unsigned unless sign.ps1 signs it.
# Each must be signed by the setup's signer (-Subject, when given, says who that must be) and
# timestamped (-Timestamped). The signature needn't be trusted here: CI's certificates are
# throwaways. 7-Zip doesn't show the uninstaller, which NSIS builds from the installer's script;
# Tauri signs it (!uninstfinalize), as the build's log shows.
#
# Usage: signed-setup.ps1 <setup.exe> [-Subject <the signer's subject>] [-Timestamped]
param(
  [Parameter(Mandatory, Position = 0)][string]$Setup,
  [string]$Subject,
  [switch]$Timestamped
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Fail([string]$message) { Write-Host "::error::$message"; exit 1 }

$seven = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
if (-not (Test-Path -LiteralPath $seven)) { Fail "no 7-Zip at $seven" }
$setupFile = Get-Item -LiteralPath $Setup
$work = Join-Path ([IO.Path]::GetTempPath()) ("beezip-signed-" + [Guid]::NewGuid().ToString('N'))

function Expand([string]$from, [string]$to) {
  & $seven x -y -bso0 -bsp0 "-o$to" $from
  if ($LASTEXITCODE) { Fail "7-Zip couldn't open $from (exit $LASTEXITCODE)" }
}

try {
  Expand $setupFile.FullName $work
  $files = @($setupFile) + @(Get-ChildItem -LiteralPath $work -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' })
  foreach ($want in 'BeeZip.exe', 'bin\beezip.exe', '$PLUGINSDIR\nsExec.dll', '$PLUGINSDIR\System.dll') {
    if (-not (Test-Path -LiteralPath (Join-Path $work $want))) { Fail "the installer holds no $want" }
  }
  $signer = (Get-AuthenticodeSignature -LiteralPath $setupFile.FullName).SignerCertificate
  if (-not $signer) { Fail "$($setupFile.Name) isn't signed" }
  if ($Subject -and $signer.Subject -ne $Subject) { Fail "$($setupFile.Name) is signed by '$($signer.Subject)', not '$Subject'" }

  $bad = @()
  foreach ($f in $files) {
    $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName
    $name = if ($f -eq $setupFile) { $f.Name } else { $f.FullName.Substring($work.Length + 1) }
    $by = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '(unsigned)' }
    $stamp = if ($sig.TimeStamperCertificate) { 'timestamped' } else { 'no timestamp' }
    Write-Host ('{0,-60} {1,-14} {2} ({3})' -f $name, $sig.Status, $by, $stamp)
    if (-not $sig.SignerCertificate) { $bad += "$name isn't signed" }
    elseif ($sig.SignerCertificate.Thumbprint -ne $signer.Thumbprint) { $bad += "$name is signed by '$by', not the setup's signer" }
    elseif ($Timestamped -and -not $sig.TimeStamperCertificate) { $bad += "$name has no timestamp" }
  }
  if ($bad) { Fail ($bad -join '; ') }
  Write-Host "all $($files.Count) programs are signed by '$($signer.Subject)'"
} finally {
  if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
