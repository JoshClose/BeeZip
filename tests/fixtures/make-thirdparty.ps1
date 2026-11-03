#Requires -Version 7
<#
.SYNOPSIS
Regenerates tests/fixtures/thirdparty/ and manifest.json (docs/M1.md §6).

.DESCRIPTION
Builds a small fixed source tree, archives it with each third-party tool, and records what every
archive must contain. This file is the record of the exact commands; the archives themselves are
committed, so the tools are only needed to regenerate them.

Tools (as on the development machine, 2026-11-02):
  7-Zip 26.00         C:\Program Files\7-Zip\7z.exe
  GNU tar 1.35        Git for Windows, C:\Program Files\Git\usr\bin\tar.exe
  bsdtar 3.8.9        C:\Windows\System32\tar.exe (liblzma, bzip2 and zstd built in)
  .NET                Compress-Archive in PowerShell 7

The GNU tar archives hold a symlink, so this needs Developer Mode (or an elevated shell).
#>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$out = Join-Path $PSScriptRoot 'thirdparty'
$sevenZip = 'C:\Program Files\7-Zip\7z.exe'
$gnuTar = 'C:\Program Files\Git\usr\bin\tar.exe'
$bsdTar = Join-Path $env:SystemRoot 'System32\tar.exe'
$password = 'beezip'
$mtime = [DateTime]::new(2026, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)

$work = Join-Path ([IO.Path]::GetTempPath()) "beezip-fixtures-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory $work | Out-Null
Push-Location $work

function Write-File([string]$path, [byte[]]$bytes) {
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    [IO.File]::WriteAllBytes($path, $bytes)
}

function Text([string]$s) { [Text.Encoding]::UTF8.GetBytes($s) }

# The source tree. Paths are relative to $work.
$random = [byte[]]::new(4096)
[Random]::new(42).NextBytes($random)
$long = 'tree/deep/directory-with-a-long-name-0123456789/another-long-directory-name-abcdefghij/file-with-a-long-name-past-100-characters.txt'
$files = [ordered]@{
    'tree/hello.txt'          = Text "Hello, BeeZip!`n"
    'tree/empty.txt'          = [byte[]]::new(0)
    'tree/docs/readme.md'     = Text (('BeeZip reads and writes archives. ' * 40) + "`n")
    'tree/data/random.bin'    = $random
    'tree/ünïcödé/名前.txt'    = Text "non-ASCII names`n"
    $long                     = Text "a long path`n"
}
foreach ($f in $files.GetEnumerator()) { Write-File (Join-Path $work $f.Key) $f.Value }

# A copy with a symlink and a hard link, for GNU tar.
Copy-Item -Recurse tree links
New-Item -ItemType SymbolicLink -Path links/link-to-hello -Target hello.txt | Out-Null
New-Item -ItemType HardLink -Path links/hard-hello -Target (Resolve-Path links/hello.txt) | Out-Null
# bsdtar 3.8.9 on Windows crashes (0xC0000005) on any non-ASCII name, so it gets a copy without.
Copy-Item -Recurse tree ascii
Remove-Item -Recurse 'ascii/ünïcödé'

foreach ($item in Get-ChildItem -Recurse -Force tree, links, ascii) {
    if (-not $item.LinkType -or $item.LinkType -eq 'HardLink') { $item.LastWriteTimeUtc = $mtime }
}
foreach ($root in 'tree', 'links', 'ascii') { (Get-Item $root).LastWriteTimeUtc = $mtime }

function Sha256([byte[]]$bytes) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

# What an archive of `$root` (tree, links or ascii) must contain.
function Expected([string]$root) {
    $entries = @()
    foreach ($f in $files.GetEnumerator()) {
        if ($root -eq 'ascii' -and $f.Key -match '[^\x00-\x7F]') { continue }
        $entries += [ordered]@{
            path = $f.Key -replace '^tree/', "$root/"; kind = 'file'
            size = $f.Value.Length; sha256 = Sha256 $f.Value
        }
    }
    if ($root -eq 'links') {
        # Which of the two hard-linked names tar stores as the file is up to tar (GNU tar takes
        # the first it meets), so both are expected as files: extraction copies the link.
        $hello = $files['tree/hello.txt']
        $entries += [ordered]@{ path = 'links/link-to-hello'; kind = 'symlink'; target = 'hello.txt' }
        $entries += [ordered]@{
            path = 'links/hard-hello'; kind = 'file'; size = $hello.Length; sha256 = Sha256 $hello
        }
    }
    , $entries
}

function Expected-Stream([string]$key) {
    $b = $files[$key]
    , @([ordered]@{ path = '*'; kind = 'file'; size = $b.Length; sha256 = Sha256 $b })
}

$fixtures = [Collections.Generic.List[object]]::new()
# `utc_mtimes`: the format stores UTC times, so extracted files must carry $mtime exactly. Zip's
# DOS times are local, which makes them depend on the machine's time zone.
# `hardlinks`, `symlinks`: how many link entries the listing shows.
function Add-Fixture($file, $producer, $command, $chain, $entries, $pw = $null, $mtimes = $false) {
    if (-not (Test-Path $file)) { throw "$file was not created by: $command" }
    $links = [int]($chain -eq 'tar' -and $file -like 'gnutar-*')
    $fixtures.Add([ordered]@{
        file = $file; producer = $producer; command = $command; chain = $chain
        password = $pw; utc_mtimes = $mtimes; hardlinks = $links; symlinks = $links
        entries = $entries
    })
}

function Run([string]$exe, [string[]]$arguments) {
    & $exe @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$exe $arguments failed with $LASTEXITCODE" }
    "$(Split-Path -Leaf $exe) $($arguments -join ' ')"
}

# 7-Zip: zip methods, encryption, an SFX, and single-file codecs.
$z = '7-Zip 26.00'
foreach ($m in 'Copy', 'Deflate', 'Deflate64', 'BZip2', 'LZMA', 'PPMd') {
    $file = "7z-$($m.ToLower()).zip"
    $cmd = Run $sevenZip @('a', '-tzip', "-mm=$m", $file, 'tree')
    Add-Fixture $file $z $cmd 'zip' (Expected 'tree')
}
$cmd = Run $sevenZip @('a', '-tzip', '-mm=Deflate', '-mem=AES256', "-p$password", '7z-aes256.zip', 'tree')
Add-Fixture '7z-aes256.zip' $z $cmd 'zip' (Expected 'tree') $password
$cmd = Run $sevenZip @('a', '-tzip', '-mm=Deflate', '-mem=ZipCrypto', "-p$password", '7z-zipcrypto.zip', 'tree')
Add-Fixture '7z-zipcrypto.zip' $z $cmd 'zip' (Expected 'tree') $password

# 7-Zip only makes 7z SFX modules, so the zip SFX is 7-Zip's deflate zip behind a minimal PE
# stub: a DOS header pointing at "PE\0\0" and an empty COFF header, padded to 512 bytes.
$stub = [byte[]]::new(512)
$stub[0] = 0x4D; $stub[1] = 0x5A                       # MZ
[BitConverter]::GetBytes([int]0x40).CopyTo($stub, 0x3C) # e_lfanew
$stub[0x40] = 0x50; $stub[0x41] = 0x45                  # PE\0\0
[BitConverter]::GetBytes([uint16]0x8664).CopyTo($stub, 0x44) # x64
[IO.File]::WriteAllBytes("$work/7z-sfx.exe", $stub + [IO.File]::ReadAllBytes("$work/7z-deflate.zip"))
Add-Fixture '7z-sfx.exe' $z 'minimal PE stub + 7z-deflate.zip' 'zip' (Expected 'tree')

foreach ($t in @(@('gzip', 'gz'), @('bzip2', 'bz2'), @('xz', 'xz'))) {
    $file = "7z-readme.md.$($t[1])"
    $cmd = Run $sevenZip @('a', "-t$($t[0])", $file, 'tree/docs/readme.md')
    Add-Fixture $file $z $cmd $t[0] (Expected-Stream 'tree/docs/readme.md')
}

# GNU tar: ustar, gnu and pax headers, each with long names, a symlink and a hard link.
$g = 'GNU tar 1.35 (Git for Windows)'
foreach ($fmt in 'ustar', 'gnu', 'pax') {
    $file = "gnutar-$fmt.tar"
    $cmd = Run $gnuTar @("--format=$fmt", '--owner=0', '--group=0', '-cf', $file, 'links')
    Add-Fixture $file $g $cmd 'tar' (Expected 'links') $null $true
}

# bsdtar (Windows tar.exe): compressed tars and a zip, of the ASCII-only tree.
$b = 'bsdtar 3.8.9 (Windows tar.exe)'
$cmd = Run $bsdTar @('-czf', 'bsdtar.tar.gz', 'ascii')
Add-Fixture 'bsdtar.tar.gz' $b $cmd 'gzip → tar' (Expected 'ascii') $null $true
$cmd = Run $bsdTar @('-cJf', 'bsdtar.tar.xz', 'ascii')
Add-Fixture 'bsdtar.tar.xz' $b $cmd 'xz → tar' (Expected 'ascii') $null $true
$cmd = Run $bsdTar @('--zstd', '-cf', 'bsdtar.tar.zst', 'ascii')
Add-Fixture 'bsdtar.tar.zst' $b $cmd 'zstd → tar' (Expected 'ascii') $null $true
$cmd = Run $bsdTar @('--format', 'zip', '-cf', 'bsdtar.zip', 'ascii')
Add-Fixture 'bsdtar.zip' $b $cmd 'zip' (Expected 'ascii')

# .NET: Compress-Archive, for its handling of non-ASCII names.
Compress-Archive -Path tree -DestinationPath dotnet.zip
Add-Fixture 'dotnet.zip' ".NET $([Environment]::Version) (PowerShell $($PSVersionTable.PSVersion) Compress-Archive)" `
    'Compress-Archive -Path tree -DestinationPath dotnet.zip' 'zip' (Expected 'tree')

Pop-Location
New-Item -ItemType Directory -Force $out | Out-Null
Get-ChildItem $out | Remove-Item -Force
foreach ($f in $fixtures) { Copy-Item (Join-Path $work $f.file) $out }
$manifest = [ordered]@{
    note = 'Generated by make-thirdparty.ps1. Paths in entries are as extracted, /-separated; "*" is the one entry of a compressed file.'
    fixtures = $fixtures
}
($manifest | ConvertTo-Json -Depth 6) -replace "`r`n", "`n" | Set-Content -NoNewline (Join-Path $PSScriptRoot 'manifest.json')
Remove-Item -Recurse -Force $work
$size = (Get-ChildItem $out | Measure-Object Length -Sum).Sum
"wrote $($fixtures.Count) fixtures ($([math]::Round($size / 1KB)) KiB) to $out"
