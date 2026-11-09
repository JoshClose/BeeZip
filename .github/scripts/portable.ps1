# The portable copy (xtask/src/dist/portable.rs): the zip holds exactly BeeZip.exe, bin\beezip.exe,
# this version's Explorer menu DLL, README.txt and the licenses; with -Subject, every program in
# it is signed by that signer (with -Timestamped, timestamped too); and its CLI runs from the
# unzipped folder. Unzipped with Windows' own Expand-Archive, as Explorer's Extract All would.
#
# Usage: portable.ps1 <BeeZip_V_x64-portable.zip> [-Subject <the signer's subject>] [-Timestamped]
param(
  [Parameter(Mandatory, Position = 0)][string]$Zip,
  [string]$Subject,
  [switch]$Timestamped
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Fail([string]$message) { Write-Host "::error::$message"; exit 1 }

$zipFile = Get-Item -LiteralPath $Zip
if ($zipFile.Name -notmatch '^BeeZip_(.+)_x64-portable\.zip$') { Fail "$($zipFile.Name) isn't named BeeZip_<version>_x64-portable.zip" }
$version = $Matches[1]
$work = Join-Path ([IO.Path]::GetTempPath()) ("beezip-portable-" + [Guid]::NewGuid().ToString('N'))

try {
  Expand-Archive -LiteralPath $zipFile.FullName -DestinationPath $work
  $want = @('BeeZip.exe', 'bin\beezip.exe', "beezip_shell_$version.dll", 'README.txt', 'LICENSE-MIT', 'LICENSE-APACHE', 'THIRD_PARTY_NOTICES.md')
  $have = @(Get-ChildItem -LiteralPath $work -Recurse -File | ForEach-Object { $_.FullName.Substring($work.Length + 1) })
  $missing = @($want | Where-Object { $_ -notin $have })
  $extra = @($have | Where-Object { $_ -notin $want })
  if ($missing) { Fail "the zip holds no $($missing -join ', ')" }
  if ($extra) { Fail "the zip holds more than it should: $($extra -join ', ')" }
  Write-Host "the zip holds: $($have -join ', ')"

  $readme = Get-Content -LiteralPath (Join-Path $work 'README.txt') -Raw
  if (-not $readme.StartsWith("BeeZip $version, portable`r`n")) { Fail "README.txt doesn't start with 'BeeZip $version, portable'" }

  if ($Subject) {
    $bad = @()
    foreach ($name in $want | Where-Object { $_ -match '\.(exe|dll)$' }) {
      $sig = Get-AuthenticodeSignature -LiteralPath (Join-Path $work $name)
      $by = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '(unsigned)' }
      $stamp = if ($sig.TimeStamperCertificate) { 'timestamped' } else { 'no timestamp' }
      Write-Host ('{0,-32} {1,-14} {2} ({3})' -f $name, $sig.Status, $by, $stamp)
      if ($by -ne $Subject) { $bad += "$name is signed by '$by', not '$Subject'" }
      elseif ($Timestamped -and -not $sig.TimeStamperCertificate) { $bad += "$name has no timestamp" }
    }
    if ($bad) { Fail ($bad -join '; ') }
  }

  $out = & (Join-Path $work 'bin\beezip.exe') --version
  if ($LASTEXITCODE) { Fail "bin\beezip.exe --version failed (exit $LASTEXITCODE)" }
  if ("$out" -notmatch [regex]::Escape($version)) { Fail "bin\beezip.exe --version said '$out', not $version" }
  Write-Host "bin\beezip.exe --version: $out"
} finally {
  if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
