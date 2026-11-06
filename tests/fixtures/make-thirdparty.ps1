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

M3 added the 7z set (docs/M3.md §6). The RAR fixtures in thirdparty/libarchive and
thirdparty/rars come from fetch-rar.ps1 and are left alone here.

M5 added names in legacy code pages (docs/M5.md §6): zips from .NET's ZipArchive given an
entry name encoding, which writes the names in that code page with no UTF-8 flag (as Explorer
on a Japanese or Russian Windows does), one from 7-Zip's -mcp, which adds Info-ZIP's Unicode
Path extra, and a tar with Latin-1 names written by Python's tarfile (`python` on the PATH).

.PARAMETER Keep
Leave archives that are already in thirdparty/ as they are, and copy only new ones. Their
contents are fixed, so the manifest still describes them; their bytes (atime and ctime fields,
AES salts) would otherwise change on every run.
#>
param([switch]$Keep)
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
# An empty file and an empty folder, for 7z (which stores both without data).
Write-File (Join-Path $work 'empties/empty.txt') ([byte[]]::new(0))
New-Item -ItemType Directory 'empties/nothing' | Out-Null

# Names only one legacy code page can write, one tree per page: the manifest's `encoding` is
# the one that reads them back.
$legacy = [ordered]@{
    cp932 = [ordered]@{ 'names-ja/日本語/表示.txt' = Text "Shift-JIS`n"; 'names-ja/ファイル.txt' = Text "Shift-JIS`n" }
    cp936 = [ordered]@{ 'names-zh/中文/文件.txt' = Text "GBK`n" }
    cp866 = [ordered]@{ 'names-ru/Привет/мир.txt' = Text "CP866`n" }
    'iso-8859-1' = [ordered]@{ 'names-latin1/café/résumé.txt' = Text "Latin-1`n" }
}
foreach ($set in $legacy.Values) {
    foreach ($f in $set.GetEnumerator()) { Write-File (Join-Path $work $f.Key) $f.Value }
}
$legacyRoots = 'names-ja', 'names-zh', 'names-ru', 'names-latin1'

foreach ($item in Get-ChildItem -Recurse -Force (@('tree', 'links', 'ascii', 'empties') + $legacyRoots)) {
    if (-not $item.LinkType -or $item.LinkType -eq 'HardLink') { $item.LastWriteTimeUtc = $mtime }
}
foreach ($root in @('tree', 'links', 'ascii', 'empties') + $legacyRoots) { (Get-Item $root).LastWriteTimeUtc = $mtime }

function Sha256([byte[]]$bytes) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

# What an archive of `$root` (tree, links, ascii or empties) must contain.
function Expected([string]$root) {
    $entries = @()
    if ($root -eq 'empties') {
        $none = [byte[]]::new(0)
        return , @([ordered]@{ path = 'empties/empty.txt'; kind = 'file'; size = 0; sha256 = Sha256 $none })
    }
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

# What an archive of one of `$legacy`'s trees must contain.
function Expected-Files($set) {
    , @(foreach ($f in $set.GetEnumerator()) {
        [ordered]@{ path = $f.Key; kind = 'file'; size = $f.Value.Length; sha256 = Sha256 $f.Value }
    })
}

function Expected-Stream([string]$key) {
    $b = $files[$key]
    , @([ordered]@{ path = '*'; kind = 'file'; size = $b.Length; sha256 = Sha256 $b })
}

$fixtures = [Collections.Generic.List[object]]::new()
# `utc_mtimes`: the format stores UTC times, so extracted files must carry $mtime exactly. Zip's
# DOS times are local, which makes them depend on the machine's time zone.
# `hardlinks`, `symlinks`: how many link entries the listing shows (GNU tar's archives have one
# of each unless `$links` says otherwise). `parts`: the other volumes of a split set, after
# `file`, the first. `encoding`: the name encoding that reads the names right, when "auto"
# doesn't.
function Add-Fixture($file, $producer, $command, $chain, $entries, $pw = $null, $mtimes = $false,
    $links = $null, [string[]]$parts = @(), $encoding = $null) {
    if (-not (Test-Path $file)) { throw "$file was not created by: $command" }
    foreach ($p in $parts) { if (-not (Test-Path $p)) { throw "$p was not created by: $command" } }
    if ($null -eq $links) {
        $n = [int]($chain -eq 'tar' -and $file -like 'gnutar-*')
        $links = @($n, $n)
    }
    $fx = [ordered]@{
        file = $file; producer = $producer; command = $command; chain = $chain
        password = $pw; utc_mtimes = $mtimes; hardlinks = $links[0]; symlinks = $links[1]
    }
    if ($parts.Count -gt 0) { $fx.parts = $parts }
    if ($encoding) { $fx.encoding = $encoding }
    $fx.entries = $entries
    $fixtures.Add($fx)
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

# 7-Zip: 7z (docs/M3.md §6). Methods, filters, encryption with and without encrypted names,
# solid and not, empty entries, a -snl symlink (on Windows a reparse buffer), a console SFX
# and a split set. 7z stores UTC FILETIMEs, so mtimes are exact. The filters run on the tree
# itself rather than on an executable, so no third-party binary is committed.
foreach ($m in 'LZMA', 'PPMd', 'BZip2', 'Deflate', 'Copy') {
    $file = "7z-$($m.ToLower()).7z"
    $cmd = Run $sevenZip @('a', '-t7z', "-m0=$m", $file, 'tree')
    Add-Fixture $file $z $cmd '7z' (Expected 'tree') $null $true
}
$sevens = [ordered]@{
    '7z-lzma2-mt.7z'  = @('-m0=LZMA2', '-mmt=4')
    '7z-bcj.7z'       = @('-m0=BCJ', '-m1=LZMA2')
    '7z-bcj2.7z'      = @('-m0=BCJ2', '-m1=LZMA', '-m2=LZMA', '-m3=LZMA', '-mb0s0:1', '-mb0s1:2', '-mb0s2:3')
    '7z-arm64.7z'     = @('-m0=ARM64', '-m1=LZMA2')
    '7z-delta.7z'     = @('-m0=Delta:4', '-m1=LZMA2')
    '7z-nonsolid.7z'  = @('-ms=off')
}
foreach ($s in $sevens.GetEnumerator()) {
    $cmd = Run $sevenZip (@('a', '-t7z') + $s.Value + @($s.Key, 'tree'))
    Add-Fixture $s.Key $z $cmd '7z' (Expected 'tree') $null $true
}
$cmd = Run $sevenZip @('a', '-t7z', "-p$password", '7z-aes.7z', 'tree')
Add-Fixture '7z-aes.7z' $z $cmd '7z' (Expected 'tree') $password $true
$cmd = Run $sevenZip @('a', '-t7z', "-p$password", '-mhe=on', '7z-aes-mhe.7z', 'tree')
Add-Fixture '7z-aes-mhe.7z' $z $cmd '7z' (Expected 'tree') $password $true
$cmd = Run $sevenZip @('a', '-t7z', '7z-empties.7z', 'empties')
Add-Fixture '7z-empties.7z' $z $cmd '7z' (Expected 'empties') $null $true
$cmd = Run $sevenZip @('a', '-t7z', '-snl', '7z-links.7z', 'links')
Add-Fixture '7z-links.7z' $z $cmd '7z' (Expected 'links') $null $true @(0, 1)
# The console module (7zCon.sfx, 189 KiB); the GUI one is 210 KiB.
$cmd = Run $sevenZip @('a', '-t7z', '-sfx7zCon.sfx', '7z-7zsfx.exe', 'tree')
Add-Fixture '7z-7zsfx.exe' $z $cmd '7z' (Expected 'tree') $null $true
$cmd = Run $sevenZip @('a', '-t7z', '-v2k', '7z-split.7z', 'tree')
Add-Fixture '7z-split.7z.001' $z $cmd '7z' (Expected 'tree') $null $true $null @('7z-split.7z.002', '7z-split.7z.003')
if (Test-Path '7z-split.7z.004') { throw '7z-split.7z has more than three parts' }

foreach ($t in @(@('gzip', 'gz'), @('bzip2', 'bz2'), @('xz', 'xz'))) {
    $file = "7z-readme.md.$($t[1])"
    $cmd = Run $sevenZip @('a', "-t$($t[0])", $file, 'tree/docs/readme.md')
    Add-Fixture $file $z $cmd $t[0] (Expected-Stream 'tree/docs/readme.md')
}

# Legacy code pages. 7-Zip writes zip names in -mcp's code page without the UTF-8 flag, but adds
# Info-ZIP's Unicode Path extra (0x7075) beside each non-ASCII one, so "auto" reads them right.
$cmd = Run $sevenZip @('a', '-tzip', '-mcp=932', '7z-cp932.zip', 'names-ja')
Add-Fixture '7z-cp932.zip' $z $cmd 'zip' (Expected-Files $legacy['cp932'])

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

# Python's tarfile: a GNU tar with Latin-1 names (no pax records, so nothing marks them UTF-8).
$py = "Python $((& python -c 'import sys; print(sys.version.split()[0])').Trim()) tarfile"
$script = "import tarfile; t = tarfile.open('python-latin1.tar', 'w', format=tarfile.GNU_FORMAT, encoding='latin-1'); t.add('names-latin1'); t.close()"
& python -I -c $script
if ($LASTEXITCODE -ne 0) { throw "python tarfile failed with $LASTEXITCODE" }
Add-Fixture 'python-latin1.tar' $py "python -c `"$script`"" 'tar' (Expected-Files $legacy['iso-8859-1']) $null $true $null @() 'iso-8859-1'

# .NET's ZipArchive given an entry name encoding writes names in it, with no flag or extra:
# only that encoding reads them right.
Add-Type -AssemblyName System.IO.Compression
[Text.Encoding]::RegisterProvider([Text.CodePagesEncodingProvider]::Instance)
function New-LegacyZip([string]$file, [int]$codePage, $set) {
    $fs = [IO.File]::Create((Join-Path $work $file))
    $zip = [IO.Compression.ZipArchive]::new($fs, [IO.Compression.ZipArchiveMode]::Create, $false,
        [Text.Encoding]::GetEncoding($codePage))
    foreach ($f in $set.GetEnumerator()) {
        $entry = $zip.CreateEntry($f.Key)
        $entry.LastWriteTime = [DateTimeOffset]::new($mtime)
        $w = $entry.Open()
        $w.Write($f.Value, 0, $f.Value.Length)
        $w.Dispose()
    }
    $zip.Dispose()
    $fs.Dispose()
}
foreach ($cp in 'cp932', 'cp936', 'cp866') {
    $file = "dotnet-$cp.zip"
    New-LegacyZip $file ([int]$cp.Substring(2)) $legacy[$cp]
    Add-Fixture $file ".NET $([Environment]::Version) ZipArchive" `
        "ZipArchive(..., entryNameEncoding: Encoding.GetEncoding($($cp.Substring(2))))" 'zip' `
        (Expected-Files $legacy[$cp]) $null $false $null @() $cp
}

# .NET: Compress-Archive, for its handling of non-ASCII names.
Compress-Archive -Path tree -DestinationPath dotnet.zip
Add-Fixture 'dotnet.zip' ".NET $([Environment]::Version) (PowerShell $($PSVersionTable.PSVersion) Compress-Archive)" `
    'Compress-Archive -Path tree -DestinationPath dotnet.zip' 'zip' (Expected 'tree')

Pop-Location
New-Item -ItemType Directory -Force $out | Out-Null
# Only this script's files: the RAR fixtures live in subfolders, from fetch-rar.ps1.
if (-not $Keep) { Get-ChildItem $out -File | Remove-Item -Force }
foreach ($f in $fixtures) {
    $names = @($f.file) + @(if ($f.Contains('parts')) { $f.parts })
    foreach ($n in $names) {
        if ($Keep -and (Test-Path (Join-Path $out $n))) { continue }
        Copy-Item (Join-Path $work $n) $out
    }
}
# fetch-rar.ps1's entries (files in subfolders) are kept as they are.
$manifestPath = Join-Path $PSScriptRoot 'manifest.json'
if (Test-Path $manifestPath) {
    $old = Get-Content -Raw $manifestPath | ConvertFrom-Json -AsHashtable
    foreach ($f in $old.fixtures) { if ($f.file -like '*/*') { $fixtures.Add($f) } }
}
$manifest = [ordered]@{
    note = 'Generated by make-thirdparty.ps1 and fetch-rar.ps1. Paths in entries are as extracted, /-separated; "*" is the one entry of a compressed file.'
    fixtures = $fixtures
}
($manifest | ConvertTo-Json -Depth 6) -replace "`r`n", "`n" | Set-Content -NoNewline $manifestPath
Remove-Item -Recurse -Force $work
$size = (Get-ChildItem $out -File | Measure-Object Length -Sum).Sum
"wrote $($fixtures.Count) fixtures ($([math]::Round($size / 1KB)) KiB) to $out"
