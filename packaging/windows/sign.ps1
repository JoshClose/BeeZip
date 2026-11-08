# BeeZip's one place that signs (docs/M6.md, 9.2). BEEZIP_SIGN picks how:
#
#   none      the default: nothing is signed, and the script says so and does nothing.
#   dev       the development certificate `cargo xtask dev-cert` makes, "CN=BeeZip Dev" in
#             CurrentUser\My (docs/M4.md, 9).
#   pfx       a certificate in a file, for an OV certificate: BEEZIP_SIGN_PFX is the .pfx and
#             BEEZIP_SIGN_PFX_PASSWORD its password. It is read in memory and never imported into
#             a certificate store.
#   artifact  Azure Artifact Signing: signtool 10.0.22621.755 or newer with the
#             Microsoft.ArtifactSigning.Client dlib (BEEZIP_ARTIFACT_DLIB, its
#             bin\x64\Azure.CodeSigning.Dlib.dll), the account in BEEZIP_ARTIFACT_ENDPOINT,
#             BEEZIP_ARTIFACT_ACCOUNT and BEEZIP_ARTIFACT_PROFILE, signed in through the Azure CLI
#             (`az login`; on CI, azure/login with OIDC, so no secret lives in the repository).
#
# Every signature is timestamped (RFC 3161, SHA-256), so it stays valid after the certificate
# expires: at BEEZIP_SIGN_TIMESTAMP, or Artifact Signing's own authority for `artifact` and
# DigiCert's for `pfx`. `dev` signatures are timestamped only when BEEZIP_SIGN_TIMESTAMP is set,
# as M4's never were: the certificate is a throwaway, and CI would depend on a public server.
#
# Usage, in Windows PowerShell or PowerShell 7:
#   sign.ps1 <file>                        sign a file: Tauri's bundle.windows.signCommand runs
#                                          this once per file, with the file as the only argument
#   sign.ps1 <file.msix> -Publisher <dn>   sign a package whose Publisher is <dn>, which must be
#                                          the certificate's subject as Windows writes it
#   sign.ps1 <file> -Signer                print the subject of the certificate that signed <file>
#                                          (nothing when it isn't signed): `xtask dist` signs the
#                                          CLI first and takes the package's publisher from it
#
# signtool is BEEZIP_SIGNTOOL, or the newest Windows SDK's x64 signtool.exe.
param(
  [Parameter(Position = 0)][string]$Path,
  [string]$Publisher,
  [switch]$Signer
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

function Fail([string]$message) {
  [Console]::Error.WriteLine("sign.ps1: $message")
  exit 1
}

$mode = 'none'
if ($env:BEEZIP_SIGN) { $mode = $env:BEEZIP_SIGN.Trim().ToLowerInvariant() }
if (@('none', 'dev', 'pfx', 'artifact') -notcontains $mode) {
  Fail "BEEZIP_SIGN is '$($env:BEEZIP_SIGN)': it must be none, dev, pfx or artifact"
}
$DevSubject = 'CN=BeeZip Dev'

function Get-Pfx {
  $file = $env:BEEZIP_SIGN_PFX
  if (-not $file -or -not (Test-Path -LiteralPath $file -PathType Leaf)) {
    Fail "BEEZIP_SIGN=pfx needs BEEZIP_SIGN_PFX, a .pfx file: '$file' isn't one"
  }
  # EphemeralKeySet: the key stays in this process's memory, never in a key or certificate store.
  $flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
  $all = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
  try { $all.Import($file, $env:BEEZIP_SIGN_PFX_PASSWORD, $flags) }
  catch { Fail "can't open $file with BEEZIP_SIGN_PFX_PASSWORD: $($_.Exception.Message)" }
  $cert = $all | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
  if (-not $cert) { Fail "$file holds no certificate with its private key" }
  $cert
}

if (-not $Path) { Fail 'usage: sign.ps1 <file> [-Publisher <subject> | -Signer]' }
$file = (Resolve-Path -LiteralPath $Path).ProviderPath
if ($Signer) {
  $cert = (Get-AuthenticodeSignature -LiteralPath $file).SignerCertificate
  if ($cert) { $cert.Subject }
  exit 0
}
if ($mode -eq 'none') {
  Write-Host "BEEZIP_SIGN is none: $file stays unsigned"
  exit 0
}

function Find-SignTool {
  if ($env:BEEZIP_SIGNTOOL) {
    if (-not (Test-Path -LiteralPath $env:BEEZIP_SIGNTOOL -PathType Leaf)) { Fail "BEEZIP_SIGNTOOL is '$($env:BEEZIP_SIGNTOOL)', which isn't a file" }
    return $env:BEEZIP_SIGNTOOL
  }
  $base = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  $found = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d+(\.\d+){3}$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'x64\signtool.exe')) } |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
  if (-not $found) { Fail "no signtool.exe in any Windows SDK under $base; install the SDK or set BEEZIP_SIGNTOOL" }
  Join-Path $found.FullName 'x64\signtool.exe'
}

$signtool = Find-SignTool
$timestamp = $env:BEEZIP_SIGN_TIMESTAMP
$metadata = $null
switch ($mode) {
  'dev' {
    if ($Publisher -and $Publisher -ne $DevSubject) { Fail "the development certificate signs packages published by '$DevSubject', not '$Publisher'" }
    $how = @('/a', '/s', 'My', '/n', 'BeeZip Dev')
  }
  'pfx' {
    $cert = Get-Pfx
    if ($Publisher -and $Publisher -ne $cert.Subject) {
      Fail "the package's publisher is '$Publisher', but $($env:BEEZIP_SIGN_PFX)'s subject is '$($cert.Subject)': they must be the same"
    }
    $how = @('/f', $env:BEEZIP_SIGN_PFX)
    if ($env:BEEZIP_SIGN_PFX_PASSWORD) { $how += @('/p', $env:BEEZIP_SIGN_PFX_PASSWORD) }
    if (-not $timestamp) { $timestamp = 'http://timestamp.digicert.com' }
  }
  'artifact' {
    $missing = @('BEEZIP_ARTIFACT_ENDPOINT', 'BEEZIP_ARTIFACT_ACCOUNT', 'BEEZIP_ARTIFACT_PROFILE', 'BEEZIP_ARTIFACT_DLIB') |
      Where-Object { -not [Environment]::GetEnvironmentVariable($_) }
    if ($missing) { Fail "BEEZIP_SIGN=artifact needs $($missing -join ', ')" }
    if (-not (Test-Path -LiteralPath $env:BEEZIP_ARTIFACT_DLIB -PathType Leaf)) { Fail "BEEZIP_ARTIFACT_DLIB is '$($env:BEEZIP_ARTIFACT_DLIB)', which isn't a file" }
    # Microsoft's page asks for "10.0.2261.755 or later", which every SDK since Windows 10's
    # first passes; the version it means is 10.0.22621.755 (and 20348's signtool doesn't work).
    $version = [version](((Get-Item -LiteralPath $signtool).VersionInfo.FileVersion -split ' ')[0])
    if ($version -lt [version]'10.0.22621.755') { Fail "$signtool is $version; Artifact Signing needs signtool 10.0.22621.755 or newer (set BEEZIP_SIGNTOOL)" }
    # Only the Azure CLI's sign-in is tried (and the environment's): the other credentials of
    # DefaultAzureCredential would each be tried first, and managed identity can wait a while on CI.
    $metadata = Join-Path ([IO.Path]::GetTempPath()) ("beezip-sign-{0}.json" -f [Guid]::NewGuid())
    @{
      Endpoint               = $env:BEEZIP_ARTIFACT_ENDPOINT
      CodeSigningAccountName = $env:BEEZIP_ARTIFACT_ACCOUNT
      CertificateProfileName = $env:BEEZIP_ARTIFACT_PROFILE
      ExcludeCredentials     = @(
        'ManagedIdentityCredential', 'WorkloadIdentityCredential', 'SharedTokenCacheCredential',
        'VisualStudioCredential', 'VisualStudioCodeCredential', 'AzurePowerShellCredential',
        'AzureDeveloperCliCredential', 'InteractiveBrowserCredential'
      )
    } | ConvertTo-Json | Set-Content -LiteralPath $metadata -Encoding ASCII
    $how = @('/dlib', $env:BEEZIP_ARTIFACT_DLIB, '/dmdf', $metadata)
    if (-not $timestamp) { $timestamp = 'http://timestamp.acs.microsoft.com' }
  }
}
$stamp = @()
if ($timestamp) { $stamp = @('/tr', $timestamp, '/td', 'SHA256') }

function Sign([string]$target) {
  # A timestamp server that doesn't answer fails the signature: try three times.
  foreach ($attempt in 1..3) {
    & $signtool sign /fd SHA256 /d BeeZip @how @stamp $target
    if ($LASTEXITCODE -eq 0) { return }
    if ($attempt -lt 3) {
      [Console]::Error.WriteLine("sign.ps1: signtool failed ($LASTEXITCODE) on $target; trying again")
      Start-Sleep -Seconds (5 * $attempt)
    }
  }
  if ($target -like '*.msix') {
    # SignerSign() 0x8007000B: the manifest's Publisher isn't the certificate's subject exactly as
    # Windows writes it; even the order of its parts counts.
    Fail "signtool couldn't sign $target; if it said 0x8007000B, the package's publisher ('$Publisher') isn't the certificate's subject"
  }
  Fail "signtool couldn't sign $target"
}

try {
  Sign $file
  # Tauri 2.12 (tauri-bundler 2.10.4) signs its copy of NSIS's plugins
  # (target\dist\<profile>\nsis\x64\Plugins\x86-unicode), but only the five its own template uses
  # (NSIS_PLUGIN_FILES). hooks.nsh also uses nsExec.dll, which would go into a signed installer
  # unsigned, and Smart App Control blocks unsigned code. So when Tauri asks for one of them, the
  # copy's nsExec.dll is signed too. The copy is made afresh for each build, from Tauri's cache,
  # which stays as it was. (An upstream bug, docs/M6.md, 16.)
  $dir = Split-Path -Parent $file
  if ((Split-Path -Leaf $dir) -eq 'x86-unicode' -and (Split-Path -Leaf (Split-Path -Parent $dir)) -eq 'Plugins') {
    foreach ($name in @('nsExec.dll')) {
      $plugin = Join-Path $dir $name
      if ((Test-Path -LiteralPath $plugin) -and -not (Get-AuthenticodeSignature -LiteralPath $plugin).SignerCertificate) {
        Sign $plugin
      }
    }
  }
} finally {
  if ($metadata) { Remove-Item -LiteralPath $metadata -ErrorAction SilentlyContinue }
}
