#Requires -Version 7
<#
.SYNOPSIS
Makes tests/fixtures/thirdparty/vhd/ and the VHD and VHDX files of tests/fixtures/malicious/
(docs/M8.md §9).

.DESCRIPTION
Hyper-V's cmdlets write the disks, unelevated (the user is in Hyper-V Administrators; CI's runners
don't have them, so the files are committed): Convert-VHD from fixed VHDs of raw disks, New-VHD for
differencing children, 4 KiB sectors and the 2 TiB disk. vhd.py (`python` on the PATH, run with
-I) makes the raw disks from committed images and writes what the cmdlets can't without mounting
a disk, which needs admin: the data in children and in the 4 KiB-sector disk, an active log, the
crafted parents. Never Get-VHD or Test-VHD here: they replay an active log into the file.

Hyper-V's files carry random GUIDs and times, so their bytes differ on every run, but not what
they hold: SHA256SUMS records each disk's content (the raw disk it was made from, read whole),
which the tests check BeeZip's reading against. Before that, every child is flattened by
Convert-VHD to a fixed VHD, which must hold the same disk (Windows reads the chain as BeeZip
must), and must leave every file as it was.

thirdparty/vhd/ (raw disks from thirdparty/7zip/):
  fat-dyn.vhd           dynamic VHD, blocks of 512 KiB, of mbr-fat.img (mbr > fat)
  fat-fixed.vhd         fixed VHD of mbr-fat.img
  odd.vhd               dynamic VHD of 6,145 sectors (mbr-fat.img, zeros, a marked last sector)
  4k-fixed.vhdx         fixed VHDX of 4 KiB logical sectors, blocks of 1 MiB, holding a disk whose
                        MBR counts 4 KiB sectors: ext2.img at sector 16, fat12.img at 96
  parents/fe.vhd        dynamic VHD, blocks of 512 KiB, of gpt-fat-ext4.img (gpt > fat, ext4)
  kids/fe-1.vhd         its child (parent `..\parents\fe.vhd`), random.bin changed in both file
                        systems (a fully present block) and free sectors of block 1 (partially)
  kids/fe-2.vhd         fe-1.vhd's child beside it: three levels
  parents/odd.vhdx      odd.vhd's disk as a dynamic VHDX, blocks of 1 MiB, without the marked
                        last sector
  kids/odd-1.avhdx      its child (parent `..\parents\odd.vhdx`, which 7-Zip can't follow), the
                        FAT's random.bin changed (a fully present block) and sectors past the
                        partition in block 1 (partially present)
  dirty.vhdx            parents/odd.vhdx with two blocks added only through its log, left active:
                        block 1, and block 3, which the disk only partly fills
  dirty-noseq.vhdx      dirty.vhdx with both log entries damaged (no sequence to replay), cut
                        after its log, past which nothing is read
  SHA256SUMS            what each disk reads as (dirty.vhdx's after replay)
The children's absolute parent paths are rewritten to C:\BeeZip\fixtures\vhd\..., so that they
name no folder of this machine: the parents are found by their relative paths, or beside.

malicious/:
  vhdx-2t-empty.vhdx    a dynamic VHDX of 2 TiB with nothing in it
  vhd-loop-a.vhd, vhd-loop-b.vhd   each the other's parent, by relative path and unique id
  vhd-self-loop.vhd     its own parent
  vhd-unc-parent.vhd    a parent named only by a UNC path, \\beezip.invalid\share\parent.vhd
#>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$out = Join-Path $PSScriptRoot 'thirdparty\vhd'
$mal = Join-Path $PSScriptRoot 'malicious'
$py = Join-Path $PSScriptRoot 'vhd.py'
$work = Join-Path ([IO.Path]::GetTempPath()) "beezip-vhd-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory $work, "$work\parents", "$work\kids", "$work\malicious", "$work\flat" |
    Out-Null

function Py {
    $o = python -I $py @args
    if ($LASTEXITCODE) { throw "vhd.py $($args -join ' ') failed" }
    $o
}
function Raw([string]$n) { Join-Path $work "raw\$n" }
function W([string]$n) { Join-Path $work $n }
function Conv([string]$src, [string]$dst, [hashtable]$a) {
    Convert-VHD -Path $src -DestinationPath $dst @a
    Write-Host "made $dst"
}
# New-VHD -Differencing refuses an .avhdx name, so such a child is made as .vhdx and renamed.
function NewDiff([string]$dst, [string]$parent, [hashtable]$a) {
    $tmp = if ($dst.EndsWith('.avhdx')) { [IO.Path]::ChangeExtension($dst, '.vhdx') } else { $dst }
    New-VHD -Path $tmp -ParentPath $parent -Differencing @a | Out-Null
    if ($tmp -ne $dst) { Move-Item $tmp $dst }
    Write-Host "made $dst"
}

Py raws (Join-Path $PSScriptRoot 'thirdparty\7zip') $work | Write-Host

# VHD.
Conv (Raw 'fat-src.vhd') (W 'fat-dyn.vhd') @{ VHDType = 'Dynamic'; BlockSizeBytes = 512KB }
Conv (Raw 'fat-src.vhd') (W 'fat-fixed.vhd') @{ VHDType = 'Fixed' }
Conv (Raw 'odd-src.vhd') (W 'odd.vhd') @{ VHDType = 'Dynamic'; BlockSizeBytes = 512KB }
Conv (Raw 'fe-src.vhd') (W 'parents\fe.vhd') @{ VHDType = 'Dynamic'; BlockSizeBytes = 512KB }
NewDiff (W 'kids\fe-1.vhd') (W 'parents\fe.vhd') @{ BlockSizeBytes = 512KB }
NewDiff (W 'kids\fe-2.vhd') (W 'kids\fe-1.vhd') @{ BlockSizeBytes = 512KB }
Py diff (W 'kids\fe-1.vhd') (Raw 'fe.img') (Raw 'fe-1.img') | Write-Host
Py diff (W 'kids\fe-2.vhd') (Raw 'fe-1.img') (Raw 'fe-2.img') | Write-Host

# VHDX.
Conv (Raw 'odd-x-src.vhd') (W 'parents\odd.vhdx') @{ VHDType = 'Dynamic'; BlockSizeBytes = 1MB }
New-VHD -Path (W '4k-fixed.vhdx') -Fixed -SizeBytes 3MB -LogicalSectorSizeBytes 4096 -BlockSizeBytes 1MB |
    Out-Null
Py fill (W '4k-fixed.vhdx') (Raw '4k.img') | Write-Host
NewDiff (W 'kids\odd-1.avhdx') (W 'parents\odd.vhdx') @{ BlockSizeBytes = 1MB }
Py diff (W 'kids\odd-1.avhdx') (Raw 'odd-x.img') (Raw 'odd-x-1.img') | Write-Host
Py log (W 'parents\odd.vhdx') (Raw 'odd-x.img') (W 'dirty.vhdx') (W 'dirty-noseq.vhdx') `
    (Raw 'dirty.img') | Write-Host

foreach ($k in 'kids\fe-1.vhd', 'kids\fe-2.vhd', 'kids\odd-1.avhdx') {
    Py paths (W $k) 'C:\BeeZip\fixtures\vhd' $work | Write-Host
}

# The malicious files.
New-VHD -Path (W 'malicious\vhdx-2t-empty.vhdx') -Dynamic -SizeBytes 2TB | Out-Null
Py malicious (W 'malicious') | Write-Host

# What each disk holds; Windows' reading of each child (Convert-VHD flattens it), which must be
# the same, and must leave every file as it was.
$disks = [ordered]@{
    'fat-dyn.vhd' = 'fat.img'; 'fat-fixed.vhd' = 'fat.img'; 'odd.vhd' = 'odd.img'
    '4k-fixed.vhdx' = '4k.img'; 'parents\fe.vhd' = 'fe.img'; 'kids\fe-1.vhd' = 'fe-1.img'
    'kids\fe-2.vhd' = 'fe-2.img'; 'parents\odd.vhdx' = 'odd-x.img'
    'kids\odd-1.avhdx' = 'odd-x-1.img'; 'dirty.vhdx' = 'dirty.img'
}
$sums = [ordered]@{}
foreach ($d in $disks.Keys) { $sums[$d] = (Py expect (W $d) (Raw $disks[$d])).Trim() }
$before = Get-ChildItem -Recurse -File $work -Exclude '*.img', '*-src.vhd' |
    Get-FileHash -Algorithm SHA256 | ForEach-Object { "$($_.Hash) $($_.Path)" }
foreach ($k in 'kids\fe-1.vhd', 'kids\fe-2.vhd', 'kids\odd-1.avhdx', 'parents\fe.vhd',
    'parents\odd.vhdx', '4k-fixed.vhdx', 'fat-dyn.vhd') {
    # A VHD has no 4 KiB sectors: that disk flattens to a fixed VHDX.
    $flat = W ("flat\" + ($k -replace '[\\.]', '-') + $(if ($k -like '4k*') { '.vhdx' } else { '.vhd' }))
    Convert-VHD -Path (W $k) -DestinationPath $flat -VHDType Fixed
    $rawFlat = "$flat.img"
    Py unfix $flat $rawFlat | Out-Null
    $got = (Get-FileHash -Algorithm SHA256 $rawFlat).Hash.ToLower()
    if ($got -ne $sums[$k]) { throw "Windows reads $k as $got, not $($sums[$k])" }
    Write-Host "Windows reads $k as expected"
}
$after = Get-ChildItem -Recurse -File $work -Exclude '*.img', '*-src.vhd' |
    Where-Object { $_.DirectoryName -ne (W 'flat') } |
    Get-FileHash -Algorithm SHA256 | ForEach-Object { "$($_.Hash) $($_.Path)" }
$changed = Compare-Object ($before | Where-Object { $_ -notmatch '\\flat\\' }) $after
if ($changed) { throw "flattening changed files: $($changed | Out-String)" }

# Into the repository.
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory $out, "$out\parents", "$out\kids" | Out-Null
foreach ($d in @($disks.Keys) + 'dirty-noseq.vhdx') { Copy-Item (W $d) (Join-Path $out $d) }
$lines = foreach ($d in $disks.Keys) { "$($sums[$d]) *$($d -replace '\\', '/')" }
[IO.File]::WriteAllText((Join-Path $out 'SHA256SUMS'), (($lines -join "`n") + "`n"))
foreach ($f in Get-ChildItem (W 'malicious')) { Copy-Item $f.FullName (Join-Path $mal $f.Name) -Force }

Get-ChildItem -Recurse -File $out, $mal -Include '*.vhd', '*.vhdx', '*.avhdx', 'SHA256SUMS' |
    Select-Object @{ n = 'File'; e = { $_.FullName.Substring($PSScriptRoot.Length + 1) } }, Length |
    Format-Table -AutoSize | Out-String | Write-Host
Remove-Item -Recurse -Force $work
