#Requires -Version 7
<#
.SYNOPSIS
Makes the merge modules, patch and transforms of tests/fixtures/thirdparty/msi/ and their records
in manifest.json (docs/M11.md §8).

.DESCRIPTION
Windows Installer's own tools write them, all already on a Windows machine with the Windows SDK:
msi.dll through its COM API (WindowsInstaller.Installer), makecab.exe, and the SDK's MsiTran.exe
and MsiMsp.exe (patchwiz.dll). CI's runners don't run it, so the files are committed. wixl 0.103
(in the fixtures image, beezip-fixtures-7z, built from make-7z.Dockerfile) builds the two
versions of a small product the patch and transforms are made from.

thirdparty/msi/:
  module.msm       a merge module (MSZIP): no Media table, its files in MergeModule.CABinet;
                   a folder at the merge point (TARGETDIR's `.` child, WiX's MergeRedirectFolder)
                   and one under it, short|long names, an empty file, a Latin-1 name in code page
                   1252, two files at one path, a modularized standard folder (SystemFolder.<G>),
                   one under ProgramFiles64Folder.<G>, CommonFilesFolder kept as it is, MsiFileHash
                   rows and a custom action's DLL in the Binary table
  module-lzx.msm   the same with LZX:21
  patch.msp        MsiMsp.exe's patch from version 1 of the product to version 2 (a.txt and
                   sub/c.txt changed, d.txt added): a delta, two whole files, both transforms
                   (TgToUp and #TgToUp), its cabinet PCW_CAB_Fixture and MsiPatchMetadata
  v1-to-v2.mst     MsiTran.exe -g from version 1 to 2
  v2-to-v1.mst     msi.dll's GenerateTransform back, with CreateTransformSummaryInfo's summary

msi.dll, makecab and patchwiz write GUIDs and times, so the files differ on every run: their
records come from the run that made the committed files, as the VHDs' do. A module's record is
where BeeZip lists each file and the bytes it was made from; a patch's or transform's is what
7-Zip 26.00 extracts (`7z x`), under its names, with `.cab` added to the cabinet's (decision 3).
Run it from the repository with Docker Desktop running and 7-Zip installed:

  pwsh tests/fixtures/make-msi-extras.ps1
#>
param(
    [string]$Sdk = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86',
    [string]$SevenZip = 'C:\Program Files\7-Zip\7z.exe',
    [string]$Image = 'beezip-fixtures-7z'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$out = Join-Path $PSScriptRoot 'thirdparty\msi'
$work = Join-Path ([IO.Path]::GetTempPath()) "beezip-msi-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory $work | Out-Null
foreach ($tool in "$Sdk\MsiTran.exe", "$Sdk\MsiMsp.exe", $SevenZip) {
    if (-not (Test-Path $tool)) { throw "missing $tool" }
}
$Wi = New-Object -ComObject WindowsInstaller.Installer
$utf8 = [Text.UTF8Encoding]::new($false)

# --- msi.dll and makecab ---------------------------------------------------------------------

# Opens (mode 3 = create, 1 = transact, 0 = read-only) a database.
function Open-MsiDb([string]$path, [int]$mode) { $Wi.OpenDatabase($path, $mode) }

function Invoke-MsiSql($db, [string]$sql) {
    $view = $db.OpenView($sql)
    $view.Execute()
    $view.Close()
}

# Inserts one row; values are strings, ints, or @{ file = 'path' } for a stream.
function Add-MsiRow($db, [string]$table, [string[]]$cols, [object[]]$values) {
    $marks = ($cols | ForEach-Object { '?' }) -join ', '
    $names = ($cols | ForEach-Object { "``$_``" }) -join ', '
    $view = $db.OpenView("INSERT INTO ``$table`` ($names) VALUES ($marks)")
    $rec = $Wi.CreateRecord($cols.Count)
    for ($i = 0; $i -lt $values.Count; $i++) {
        $v = $values[$i]
        if ($null -eq $v) { continue }
        if ($v -is [hashtable]) { $rec.SetStream($i + 1, $v.file) }
        elseif ($v -is [int]) { $rec.IntegerData($i + 1) = $v }
        else { $rec.StringData($i + 1) = [string]$v }
    }
    $view.Execute($rec)
    $view.Close()
}

# Summary information: PID -> value.
function Set-MsiSummary($db, [hashtable]$props) {
    $si = $db.SummaryInformation(20)
    foreach ($k in $props.Keys) { $si.Property([int]$k) = $props[$k] }
    $si.Persist()
}

function Close-MsiDb($db) {
    $db.Commit()
    [Runtime.InteropServices.Marshal]::ReleaseComObject($db) | Out-Null
}

# A cabinet from makecab: $files is an ordered list of @(name in the cabinet, source path).
function New-Cab([string]$path, $files, [string]$compression) {
    $dir = Split-Path $path
    $ddf = "$path.ddf"
    $type, $mem = $compression.Split(':')
    $lines = @(
        '.Set CabinetNameTemplate=' + (Split-Path $path -Leaf)
        '.Set DiskDirectoryTemplate=' + $dir
        '.Set Cabinet=on'
        '.Set Compress=on'
        '.Set CompressionType=' + $type
        '.Set MaxDiskSize=0'
        '.Set RptFileName=nul'
        '.Set InfFileName=nul'
        '.Set UniqueFiles=off'
    )
    if ($mem) { $lines += '.Set CompressionMemory=' + $mem }
    foreach ($f in $files) { $lines += ('"{0}" "{1}"' -f $f[1], $f[0]) }
    Set-Content -Path $ddf -Value $lines -Encoding ascii
    & "$env:SystemRoot\System32\makecab.exe" /F $ddf | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "makecab failed for $path" }
}

function Write-Text([string]$path, [string]$text) {
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    [IO.File]::WriteAllText($path, $text, $utf8)
}

function Get-Sha256([byte[]]$bytes) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

# --- Merge modules ---------------------------------------------------------------------------

$G = '8D5E0F2A_1B2C_4D3E_9F40_112233445566'
# Each file: its key, component, FileName, contents and where BeeZip lists it.
$moduleFiles = @(
    , @("readme.txt.$G", "Top.$G", 'README.TXT|readme.txt', "readme at the merge point`n", 'readme.txt')
    , @("empty.txt.$G", "Top.$G", 'empty.txt', '', 'empty.txt')
    , @("guide.txt.$G", "Docs.$G", 'GUIDE.TXT|guide.txt', ('guide ' * 400), 'Documentation/guide.txt')
    , @("cafe.txt.$G", "Docs.$G", ('CAFE.TXT|caf' + [char]0xE9 + '.txt'), "Latin-1 name`n", ('Documentation/caf' + [char]0xE9 + '.txt'))
    , @("dup.txt.$G", "Docs.$G", 'dup.txt', "first alternate`n", 'Documentation/dup.txt')
    , @("dup2.txt.$G", "Docs2.$G", 'dup.txt', "second alternate`n", "Documentation/dup.dup2.txt.$G.txt")
    , @("tool.dll.$G", "Vendor.$G", 'tool.dll', ('MZ tool ' * 2000), 'ProgramFiles64Folder/BeeZip Module/tool.dll')
    , @("shared.dat.$G", "Shared.$G", 'shared.dat', ('shared ' * 300), 'CommonFilesFolder/Shared/shared.dat')
    , @("sys.dll.$G", "Sys.$G", 'sys.dll', ('MZ sys ' * 500), 'SystemFolder/sys.dll')
)
$caBytes = [byte[]](@(0x4D, 0x5A) + (1..200 | ForEach-Object { $_ % 256 }))

function New-Module([string]$path, [string]$compression) {
    $dir = Join-Path $work ([IO.Path]::GetFileNameWithoutExtension($path))
    New-Item -ItemType Directory -Force $dir | Out-Null
    $cab = @()
    $i = 0
    foreach ($f in $moduleFiles) {
        $i++
        $src = Join-Path $dir "f$i.bin"
        [IO.File]::WriteAllText($src, $f[3], $utf8)
        $cab += , @($f[0], $src)
    }
    $cabPath = Join-Path $dir 'MergeModule.CABinet'
    New-Cab $cabPath $cab $compression

    $db = Open-MsiDb $path 3
    $cp = Join-Path $dir 'cp'
    New-Item -ItemType Directory $cp | Out-Null
    Set-Content -Path (Join-Path $cp '_ForceCodepage.idt') -Value @('', '', "1252`t_ForceCodepage") -Encoding ascii
    $db.Import($cp, '_ForceCodepage.idt')
    Invoke-MsiSql $db 'CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Directory`)'
    Invoke-MsiSql $db 'CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)'
    Invoke-MsiSql $db 'CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL LOCALIZABLE, `FileSize` LONG NOT NULL, `Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, `Sequence` LONG NOT NULL PRIMARY KEY `File`)'
    Invoke-MsiSql $db 'CREATE TABLE `MsiFileHash` (`File_` CHAR(72) NOT NULL, `Options` SHORT NOT NULL, `HashPart1` LONG NOT NULL, `HashPart2` LONG NOT NULL, `HashPart3` LONG NOT NULL, `HashPart4` LONG NOT NULL PRIMARY KEY `File_`)'
    Invoke-MsiSql $db 'CREATE TABLE `ModuleSignature` (`ModuleID` CHAR(72) NOT NULL, `Language` SHORT NOT NULL, `Version` CHAR(32) NOT NULL PRIMARY KEY `ModuleID`, `Language`)'
    Invoke-MsiSql $db 'CREATE TABLE `ModuleComponents` (`Component` CHAR(72) NOT NULL, `ModuleID` CHAR(72) NOT NULL, `Language` SHORT NOT NULL PRIMARY KEY `Component`, `ModuleID`, `Language`)'
    Invoke-MsiSql $db 'CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)'
    Invoke-MsiSql $db 'CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL LOCALIZABLE PRIMARY KEY `Property`)'
    foreach ($d in @(
            , @('TARGETDIR', $null, 'SourceDir')
            , @("MergeRedirectFolder.$G", 'TARGETDIR', '.')
            , @("Docs.$G", "MergeRedirectFolder.$G", 'DOCS|Documentation')
            , @("ProgramFiles64Folder.$G", 'TARGETDIR', 'PFiles64')
            , @("Vendor.$G", "ProgramFiles64Folder.$G", 'BEEZIP|BeeZip Module')
            , @('CommonFilesFolder', 'TARGETDIR', 'CFiles')
            , @("Shared.$G", 'CommonFilesFolder', 'Shared')
            , @("SystemFolder.$G", 'TARGETDIR', 'System')
        )) { Add-MsiRow $db 'Directory' @('Directory', 'Directory_Parent', 'DefaultDir') $d }
    $n = 0
    foreach ($c in @(
            , @("Top.$G", "MergeRedirectFolder.$G")
            , @("Docs.$G", "Docs.$G")
            , @("Docs2.$G", "Docs.$G")
            , @("Vendor.$G", "Vendor.$G")
            , @("Shared.$G", "Shared.$G")
            , @("Sys.$G", "SystemFolder.$G")
        )) {
        $n++
        $id = '{' + ('11111111-2222-3333-4444-{0:D12}' -f $n) + '}'
        Add-MsiRow $db 'Component' @('Component', 'ComponentId', 'Directory_', 'Attributes') @($c[0], $id, $c[1], 0)
        Add-MsiRow $db 'ModuleComponents' @('Component', 'ModuleID', 'Language') @($c[0], "BeeZipFixture.$G", 0)
    }
    $seq = 0
    foreach ($f in $moduleFiles) {
        $seq++
        $src = $cab[$seq - 1][1]
        $size = (Get-Item $src).Length
        Add-MsiRow $db 'File' @('File', 'Component_', 'FileName', 'FileSize', 'Attributes', 'Sequence') @($f[0], $f[1], $f[2], [int]$size, 512, $seq)
        if ($size -gt 0) {
            $h = $Wi.FileHash($src, 0)
            $parts = 1..4 | ForEach-Object { [int]$h.IntegerData($_) }
            Add-MsiRow $db 'MsiFileHash' @('File_', 'Options', 'HashPart1', 'HashPart2', 'HashPart3', 'HashPart4') @($f[0], 0, $parts[0], $parts[1], $parts[2], $parts[3])
        }
    }
    Add-MsiRow $db 'ModuleSignature' @('ModuleID', 'Language', 'Version') @("BeeZipFixture.$G", 0, '1.2.3')
    $ca = Join-Path $dir 'ca.dll'
    [IO.File]::WriteAllBytes($ca, $caBytes)
    Add-MsiRow $db 'Binary' @('Name', 'Data') @("CustomAction.$G", @{ file = $ca })
    Add-MsiRow $db 'Property' @('Property', 'Value') @('ModuleProperty', 'x')
    Add-MsiRow $db '_Streams' @('Name', 'Data') @('MergeModule.CABinet', @{ file = $cabPath })
    Set-MsiSummary $db @{ 2 = 'Merge Module'; 3 = 'BeeZip fixture module'; 4 = 'BeeZip'; 7 = 'x64;0'; 9 = "{$($G.Replace('_', '-'))}"; 14 = 200; 15 = 2; 19 = 2 }
    Close-MsiDb $db
}

# --- The product, two versions, by wixl --------------------------------------------------------

$wxs = @'
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="AAAAAAAA-1111-2222-3333-444444444444" Name="BeeZip Patch Fixture" Language="1033" Version="1.0.@V@" Manufacturer="BeeZip" UpgradeCode="BBBBBBBB-1111-2222-3333-444444444444">
    <Package Id="CCCCCCCC-1111-2222-3333-00000000000@V@" InstallerVersion="200" Compressed="$(var.Compressed)" InstallScope="perUser" />
    <?if $(var.Compressed) = yes ?>
    <Media Id="1" Cabinet="data.cab" EmbedCab="yes" />
    <?else?>
    <Media Id="1" />
    <?endif?>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="LocalAppDataFolder">
        <Directory Id="INSTALLDIR" Name="BeeZip Patch Fixture">
          <Component Id="CompA" Guid="DDDDDDDD-1111-2222-3333-000000000001"><File Id="a.txt" Source="a.txt" KeyPath="yes" /></Component>
          <Component Id="CompB" Guid="DDDDDDDD-1111-2222-3333-000000000002"><File Id="b.txt" Source="b.txt" KeyPath="yes" /></Component>
          <Directory Id="SUBDIR" Name="sub">
            <Component Id="CompC" Guid="DDDDDDDD-1111-2222-3333-000000000003"><File Id="c.txt" Source="sub/c.txt" KeyPath="yes" /></Component>
          </Directory>
          @D@
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="Main" Level="1"><ComponentRef Id="CompA" /><ComponentRef Id="CompB" /><ComponentRef Id="CompC" />@DREF@</Feature>
  </Product>
</Wix>
'@
foreach ($v in 1, 2) {
    $vd = Join-Path $work "v$v"
    $which = @('first', 'second')[$v - 1]
    Write-Text "$vd\a.txt" @("alpha version one`n", "alpha version two, longer`n")[$v - 1]
    Write-Text "$vd\b.txt" "bravo unchanged`n"
    $lines = 0..1999 | ForEach-Object { if ($_ % 7 -eq 0) { "line $_ of c, $which version" } else { "line $_ of c, first version" } }
    Write-Text "$vd\sub\c.txt" (($lines -join "`n") + "`n")
    $d = ''
    $dref = ''
    if ($v -eq 2) {
        Write-Text "$vd\d.txt" "delta, new in v2`n"
        $d = '<Component Id="CompD" Guid="DDDDDDDD-1111-2222-3333-000000000004"><File Id="d.txt" Source="d.txt" KeyPath="yes" /></Component>'
        $dref = '<ComponentRef Id="CompD" />'
    }
    Write-Text "$vd\p.wxs" $wxs.Replace('@V@', "$v").Replace('@D@', $d).Replace('@DREF@', $dref)
}
# wixl warns twice about the Media row for Compressed="no" (docs/UPSTREAM.md); the images below
# fix what it leaves out.
docker run --rm --entrypoint bash -v "${work}:/w" $Image -c 'set -e; for v in 1 2; do cd /w/v$v; wixl -D Compressed=yes -o /w/c$v.msi p.wxs; wixl -D Compressed=no -o /w/u$v.msi p.wxs; done'
if ($LASTEXITCODE -ne 0) { throw 'wixl failed' }

# --- Transforms and the patch ------------------------------------------------------------------

# The uncompressed images patchwiz reads: the package and its files at their source paths, its
# Media row and word count fixed (wixl writes neither for Compressed="no": docs/UPSTREAM.md).
foreach ($v in 1, 2) {
    $img = Join-Path $work "img$v"
    New-Item -ItemType Directory -Force "$img\BeeZip Patch Fixture\sub" | Out-Null
    Copy-Item "$work\u$v.msi" "$img\fixture.msi"
    foreach ($f in Get-ChildItem -Recurse -File "$work\v$v" -Exclude *.wxs) {
        $rel = $f.FullName.Substring("$work\v$v".Length + 1)
        Copy-Item $f.FullName "$img\BeeZip Patch Fixture\$rel"
    }
    $db = Open-MsiDb "$img\fixture.msi" 1
    $view = $db.OpenView('SELECT `Sequence` FROM `File`')
    $view.Execute()
    $last = 0
    while ($null -ne ($rec = $view.Fetch())) { $last = [Math]::Max($last, [int]$rec.IntegerData(1)) }
    $view.Close()
    Invoke-MsiSql $db 'DELETE FROM `Media`'
    Add-MsiRow $db 'Media' @('DiskId', 'LastSequence') @(1, [int]$last)
    Set-MsiSummary $db @{ 15 = 8 }
    Close-MsiDb $db
}

& "$Sdk\MsiTran.exe" -g "$work\c1.msi" "$work\c2.msi" "$work\v1-to-v2.mst" | Out-Null
if (-not (Test-Path "$work\v1-to-v2.mst")) { throw 'MsiTran made no transform' }
$new = Open-MsiDb "$work\c1.msi" 0
$old = Open-MsiDb "$work\c2.msi" 0
$new.GenerateTransform($old, "$work\v2-to-v1.mst") | Out-Null
$new.CreateTransformSummaryInfo($old, "$work\v2-to-v1.mst", 0x0001, 0x0808) | Out-Null

# The patch creation properties (PCP): every table patchwiz.dll reads, every PatchMetadata
# property it names, ApiPatchingSymbolFlags in hex.
$pcp = "$work\fixture.pcp"
$db = Open-MsiDb $pcp 3
Invoke-MsiSql $db 'CREATE TABLE `Properties` (`Name` CHAR(72) NOT NULL, `Value` CHAR(0) PRIMARY KEY `Name`)'
Invoke-MsiSql $db 'CREATE TABLE `ImageFamilies` (`Family` CHAR(8) NOT NULL, `MediaSrcPropName` CHAR(72), `MediaDiskId` SHORT, `FileSequenceStart` LONG, `DiskPrompt` CHAR(128), `VolumeLabel` CHAR(32) PRIMARY KEY `Family`)'
Invoke-MsiSql $db 'CREATE TABLE `UpgradedImages` (`Upgraded` CHAR(13) NOT NULL, `MsiPath` CHAR(255) NOT NULL, `PatchMsiPath` CHAR(255), `SymbolPaths` CHAR(255), `Family` CHAR(8) NOT NULL PRIMARY KEY `Upgraded`)'
Invoke-MsiSql $db 'CREATE TABLE `TargetImages` (`Target` CHAR(13) NOT NULL, `MsiPath` CHAR(255) NOT NULL, `SymbolPaths` CHAR(255), `Upgraded` CHAR(13) NOT NULL, `Order` SHORT NOT NULL, `ProductValidateFlags` CHAR(16), `IgnoreMissingSrcFiles` SHORT NOT NULL PRIMARY KEY `Target`)'
Invoke-MsiSql $db 'CREATE TABLE `PatchMetadata` (`Company` CHAR(72), `Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL PRIMARY KEY `Company`, `Property`)'
Invoke-MsiSql $db 'CREATE TABLE `PatchSequence` (`PatchFamily` CHAR(72) NOT NULL, `Target` CHAR(72), `Sequence` CHAR(72), `Supersede` LONG PRIMARY KEY `PatchFamily`, `Target`)'
$tmp = "$work\pcp-tmp"
foreach ($p in @(
        , @('PatchGUID', '{EEEEEEEE-1111-2222-3333-444444444444}')
        , @('OutputPath', "$tmp\")
        , @('PatchOutputPath', "$work\patch.msp")
        , @('AllowProductCodeMismatches', '0')
        , @('AllowProductVersionMajorMismatches', '0')
        , @('IncludeWholeFilesOnly', '0')
        , @('MinimumRequiredMsiVersion', '300')
        , @('ApiPatchingSymbolFlags', '0x00000000')
        , @('OptimizePatchSizeForLargeFiles', '1')
    )) { Add-MsiRow $db 'Properties' @('Name', 'Value') $p }
Add-MsiRow $db 'ImageFamilies' @('Family', 'MediaSrcPropName', 'MediaDiskId', 'FileSequenceStart') @('Fixture', 'FixtureSrc', 2, 100)
Add-MsiRow $db 'UpgradedImages' @('Upgraded', 'MsiPath', 'Family') @('Up', "$work\img2\fixture.msi", 'Fixture')
Add-MsiRow $db 'TargetImages' @('Target', 'MsiPath', 'Upgraded', 'Order', 'ProductValidateFlags', 'IgnoreMissingSrcFiles') @('Tg', "$work\img1\fixture.msi", 'Up', 1, '0x00000922', 0)
foreach ($m in @(
        , @('DisplayName', 'BeeZip patch fixture 1.0.2')
        , @('Description', 'Changes a.txt and sub\c.txt, adds d.txt')
        , @('ManufacturerName', 'BeeZip')
        , @('Classification', 'Update')
        , @('AllowRemoval', '1')
        , @('TargetProductName', 'BeeZip Patch Fixture')
        , @('MoreInfoURL', 'https://example.invalid/beezip-fixture')
        , @('CreationTimeUTC', '11-13-26 00:00')
    )) { Add-MsiRow $db 'PatchMetadata' @('Property', 'Value') $m }
Add-MsiRow $db 'PatchSequence' @('PatchFamily', 'Sequence') @('BeeZipFixture', '1.0.2.0')
Close-MsiDb $db
# Views and records hold their database open: let them go before patchwiz opens the images.
$view = $null; $rec = $null; $db = $null; $new = $null; $old = $null
[GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
& "$Sdk\MsiMsp.exe" -s $pcp -p "$work\patch.msp" -l "$work\msimsp.log" -f $tmp | Out-Null
if (-not (Test-Path "$work\patch.msp")) { throw "MsiMsp made no patch (see $work\msimsp.log)" }

New-Module "$work\module.msm" 'MSZIP'
New-Module "$work\module-lzx.msm" 'LZX:21'

# --- Into thirdparty/msi, with their records ---------------------------------------------------

New-Item -ItemType Directory -Force $out | Out-Null
$made = 'module.msm', 'module-lzx.msm', 'patch.msp', 'v1-to-v2.mst', 'v2-to-v1.mst'
foreach ($f in $made) { Copy-Item "$work\$f" (Join-Path $out $f) -Force }

$records = [Collections.Generic.List[object]]::new()
$common = [ordered]@{ chain = 'msi'; native = $true; password = $null; utc_mtimes = $false; hardlinks = 0; symlinks = 0 }
foreach ($m in @(@('module.msm', 'MSZIP'), @('module-lzx.msm', 'LZX:21'))) {
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($f in $moduleFiles) {
        $bytes = $utf8.GetBytes($f[3])
        $entries.Add([ordered]@{ path = $f[4]; kind = 'file'; size = $bytes.Length; sha256 = Get-Sha256 $bytes })
    }
    $entries.Add([ordered]@{ path = "[Binary]/CustomAction.$G"; kind = 'file'; size = $caBytes.Length; sha256 = Get-Sha256 $caBytes })
    $records.Add([ordered]@{
            file = "msi/$($m[0])"; producer = 'Windows Installer (msi.dll) and makecab.exe, Windows 11'
            command = "make-msi-extras.ps1: a merge module through msi.dll's COM API, MergeModule.CABinet by makecab ($($m[1]))"
        } + $common + [ordered]@{
            levels = @('msm', 'cab')
            note = "BeeZip's own reader (docs/M11.md §4.1): each file where the module puts it, with the bytes it was made from (make-msi-extras.ps1). 7-Zip lists the module's streams instead, and its cabinet's files by their keys."
            entries = $entries
        })
}
$seven = (& $SevenZip i | Select-String -Pattern '^7-Zip.*?(\d+\.\d+)' | Select-Object -First 1).Matches[0].Groups[1].Value
foreach ($m in @(
        @('patch.msp', 'msp', 'MsiMsp.exe (patchwiz.dll, Windows SDK 10.0.26100) from wixl 0.103 builds', 'make-msi-extras.ps1: MsiMsp.exe -s fixture.pcp -p patch.msp'),
        @('v1-to-v2.mst', 'mst', 'MsiTran.exe (Windows SDK 10.0.26100) from wixl 0.103 builds', 'MsiTran.exe -g c1.msi c2.msi v1-to-v2.mst'),
        @('v2-to-v1.mst', 'mst', 'Windows Installer (msi.dll) from wixl 0.103 builds', "make-msi-extras.ps1: GenerateTransform and CreateTransformSummaryInfo, c1.msi against c2.msi")
    )) {
    $x = Join-Path $work "x-$($m[0])"
    & $SevenZip x -y "-o$x" (Join-Path $out $m[0]) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7-Zip couldn't extract $($m[0])" }
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($d in Get-ChildItem -Recurse -Directory $x | Sort-Object FullName) {
        $entries.Add([ordered]@{ path = $d.FullName.Substring($x.Length + 1).Replace('\', '/'); kind = 'folder' })
    }
    foreach ($f in Get-ChildItem -Recurse -File $x | Sort-Object FullName) {
        $bytes = [IO.File]::ReadAllBytes($f.FullName)
        $path = $f.FullName.Substring($x.Length + 1).Replace('\', '/')
        $cab = $bytes.Length -ge 36 -and [Text.Encoding]::ASCII.GetString($bytes, 0, 4) -eq 'MSCF'
        if ($cab -and -not $path.EndsWith('.cab', [StringComparison]::OrdinalIgnoreCase)) { $path += '.cab' }
        $entries.Add([ordered]@{ path = $path; kind = 'file'; size = $bytes.Length; sha256 = Get-Sha256 $bytes })
    }
    $records.Add([ordered]@{
            file = "msi/$($m[0])"; producer = $m[2]; command = $m[3]
        } + $common + [ordered]@{
            levels = @($m[1])
            note = "BeeZip's own reader (docs/M11.md §4.2): the compound file's storages and streams, as 7-Zip $seven extracts them (``7z x``) under its names, with ``.cab`` added to the cabinet's."
            entries = $entries
        })
}
$json = Join-Path $work 'records.json'
[IO.File]::WriteAllText($json, (ConvertTo-Json -InputObject $records.ToArray() -Depth 6), $utf8)

# Each record replaces the one of its file; new ones go after the other msi/ records, or at the end.
$merge = @'
import json, sys
manifest_path, records_path = sys.argv[1], sys.argv[2]
manifest = json.load(open(manifest_path, encoding='utf-8'))
records = json.load(open(records_path, encoding='utf-8'))
mine = {r['file'] for r in records}
old = manifest['fixtures']
at = next((i for i, r in enumerate(old) if r['file'] in mine), None)
rest = [r for r in old if r['file'] not in mine]
if at is None:
    at = len(rest)
else:
    at = sum(1 for r in old[:at] if r['file'] not in mine)
manifest['fixtures'] = rest[:at] + records + rest[at:]
with open(manifest_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(json.dumps(manifest, indent=2, ensure_ascii=False))
print(len(records), 'records')
'@
$py = Join-Path $work 'merge.py'
[IO.File]::WriteAllText($py, $merge, $utf8)
python -I $py (Join-Path $PSScriptRoot 'manifest.json') $json
if ($LASTEXITCODE -ne 0) { throw 'merging the records failed' }

Get-ChildItem $out | Select-Object Name, Length | Format-Table -AutoSize
# msi.dll lets go of the last database only when its objects are collected.
[GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
Remove-Item -Recurse -Force $work
