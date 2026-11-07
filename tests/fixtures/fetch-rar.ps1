#Requires -Version 7
<#
.SYNOPSIS
Fetches the RAR fixtures into tests/fixtures/thirdparty/libarchive and .../rars, and records them in
manifest.json (docs/M3.md §6).

.DESCRIPTION
WinRAR isn't needed: these archives were made by real WinRAR versions for other projects' tests.

  libarchive 3.8.11 (BSD-2-Clause)  libarchive/test/*.uu at the v3.8.11 tag, uudecoded. The
                                    broken ones go to libarchive/broken/ and aren't in the
                                    manifest: each must fail with Corrupt or match 7-Zip.
  rars 0.12.3 (Apache-2.0)          two RAR 1.5-4 files from the crate's tests: a RAR 3.00
                                    archive with encrypted headers, and a RAR 4.20 one with a
                                    sub-second mtime.

Every file is checked against the SHA-256 below. The expected entries come from 7-Zip 26.00,
which reads RAR 1.5-7 and decrypts it: `7z l -slt` for the listing, `7z x` for the bytes.

.PARAMETER Record
Print the SHA-256 table for the files as fetched, instead of checking it.
#>
param([switch]$Record)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sevenZip = 'C:\Program Files\7-Zip\7z.exe'
# 7z prints names as UTF-8 with -sccUTF-8; read its output that way.
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$tag = 'v3.8.11'
$base = "https://raw.githubusercontent.com/libarchive/libarchive/$tag"
$out = Join-Path $PSScriptRoot 'thirdparty'

# name => password(s): one password for the archive, or the archive's then an entry's.
$good = [ordered]@{
    'test_read_format_rar.rar'                         = $null
    'test_read_format_rar_compress_normal.rar'         = $null
    'test_read_format_rar_compress_best.rar'           = $null
    'test_read_format_rar_unicode.rar'                 = $null
    'test_read_format_rar_windows.rar'                 = $null
    'test_read_format_rar4_solid_encrypted.rar'        = @('password')
    'test_read_format_rar4_encrypted.rar'              = @('password', 'password2')
    'test_read_format_rar4_encrypted_filenames.rar'    = @('password')
    'test_read_format_rar_multivolume.part0001.rar'    = $null
    'test_read_format_rar_sfx.exe'                     = $null
    'test_read_format_rar5_stored.rar'                 = $null
    'test_read_format_rar5_compressed.rar'             = $null
    'test_read_format_rar5_solid.rar'                  = $null
    'test_read_format_rar5_multiple_files.rar'         = $null
    'test_read_format_rar5_multiarchive_solid.part01.rar' = $null
    'test_read_format_rar5_encrypted.rar'              = @('password', 'password2')
    'test_read_format_rar5_encrypted_filenames.rar'    = @('password')
    'test_read_format_rar5_symlink.rar'                = $null
    'test_read_format_rar5_hardlink.rar'               = $null
    'test_read_format_rar5_unicode.rar'                = $null
    'test_read_format_rar5_win32.rar'                  = $null
    'test_read_format_rar5_blake2.rar'                 = $null
}
$parts = @{
    'test_read_format_rar_multivolume.part0001.rar' = 2..4 | ForEach-Object { "test_read_format_rar_multivolume.part000$_.rar" }
    'test_read_format_rar5_multiarchive_solid.part01.rar' = 2..4 | ForEach-Object { "test_read_format_rar5_multiarchive_solid.part0$_.rar" }
}
$broken = @(
    'test_read_format_rar5_bad_tables.rar'
    'test_read_format_rar5_block_size_is_too_small.rar'
    'test_read_format_rar5_decode_number_out_of_bounds_read.rar'
    'test_read_format_rar5_distance_overflow.rar'
    'test_read_format_rar5_invalid_dict_reference.rar'
    'test_read_format_rar5_leftshift1.rar'
    'test_read_format_rar5_leftshift2.rar'
    'test_read_format_rar5_readtables_overflow.rar'
    'test_read_format_rar5_redir_overflow.rar'
    'test_read_format_rar5_truncated_huff.rar'
    'test_read_format_rar5_unpacked_size_exceeds_declared.rar'
    'test_read_format_rar5_window_buf_and_size_desync.rar'
    'test_read_format_rar_endarc_huge.rar'
    'test_read_format_rar_invalid1.rar'
    'test_read_format_rar_newsub_huge.rar'
    'test_read_format_rar_noeof.rar'
    'test_read_format_rar_overflow.rar'
    'test_read_format_rar_ppmd_use_after_free.rar'
    'test_read_format_rar_ppmd_use_after_free2.rar'
    'test_read_format_rar_symlink_huge.rar'
)
$rars = [ordered]@{
    'header_rar300_password.rar' = @('tests/fixtures/rar15_40/encrypted/header_rar300_password.rar', @('password'))
    'ext_time_rar420.rar'        = @('tests/fixtures/rar15_40/rar420/ext_time_rar420.rar', $null)
}

# Names 7-Zip gets wrong. RAR 2.x-4 for Unix stores names in the locale's encoding (UTF-8)
# without the Unicode flag, and 7-Zip decodes them in the OEM code page; libarchive's own test
# expects the UTF-8 name, and so does BeeZip.
$nameFixes = @{
    'abcdefghijklmnopqrsπâåπé╣πâê.txt' = 'abcdefghijklmnopqrsテスト.txt'
}

$sha256 = @{
    'libarchive/test_read_format_rar.rar' = 'd421b86f6290aefad61b2a36737253b2b30fe27c156bd95abfc230f24fe0307e'
    'libarchive/test_read_format_rar_compress_normal.rar' = '7d32e2ef511d0ade372345440838165df828197eff4d7816880dafde690cce03'
    'libarchive/test_read_format_rar_compress_best.rar' = '7005b3c6e169ae559f0183c5f0640fdd201b329cf61838c1ca45725949fe0e06'
    'libarchive/test_read_format_rar_unicode.rar' = '3dc3d2a8f3f6cbfeeb6f45b3bb09fa7b2bf4b52e10e80df29217fdeaa9dbda45'
    'libarchive/test_read_format_rar_windows.rar' = '8d689455e9ecd92c19426604e2360b5ef8eb023890fe46aabbe2864260b70fc9'
    'libarchive/test_read_format_rar4_solid_encrypted.rar' = '428d44a21042069bbc1891c30a66c48f55540aa37dd8b7ff92c39c5914e3a4a6'
    'libarchive/test_read_format_rar4_encrypted.rar' = 'c30dc6d10e59aaab1c863afa469d188c644a22d67d6e50ac7ca887e520f5fc8b'
    'libarchive/test_read_format_rar4_encrypted_filenames.rar' = '0201a8cd86c15c117c7541d841c36c0dbabb4824396f19889db5f7d5364e7ef9'
    'libarchive/test_read_format_rar_multivolume.part0001.rar' = '6c4d7f55cbf0a44aa0cafb283b0fd954ef625c9afc2fbe1cce4f201fc2508c63'
    'libarchive/test_read_format_rar_sfx.exe' = '0a413b8fbd2242a2cf94e7c4bc998726bff3ea949182afa764b725227155cd4f'
    'libarchive/test_read_format_rar5_stored.rar' = '35d75e315d164d2e329afc28f7d844f013271b4fcffd4ddd78efcdd114a383a7'
    'libarchive/test_read_format_rar5_compressed.rar' = '68f9d7e2662cd5bc5607ba9c6bf1edbf121cf3b08011a7d8643091791750a7c8'
    'libarchive/test_read_format_rar5_solid.rar' = '1149dda288494ab6c954d0e3f2a8831318aaf9c69e7da741729bb0c681f924b5'
    'libarchive/test_read_format_rar5_multiple_files.rar' = '65305723965a55a89b7e120d54807c6ae30b69532712aa20d3934296799e923b'
    'libarchive/test_read_format_rar5_multiarchive_solid.part01.rar' = '6607f575dad0b28aaeb02298b4c04a0e5a606e77f952127d2d9e346f60616a26'
    'libarchive/test_read_format_rar5_encrypted.rar' = '72b69a1d5f5757511e683a9207166c60e91ce0846ae446b8b332b085f9e0ba48'
    'libarchive/test_read_format_rar5_encrypted_filenames.rar' = 'b2b98004c9cbf4f2a4000380ad47a16dea99f2d50835b1602c40d724eb82c300'
    'libarchive/test_read_format_rar5_symlink.rar' = 'a7336968564786ea5ff106fff2f6ef8dfd8ad5ecca86fbd1db3d63ba42bcd29a'
    'libarchive/test_read_format_rar5_hardlink.rar' = '2a0494afad63dcf7a5522afd593bde0cb42f53744888397febf112c00853f3d0'
    'libarchive/test_read_format_rar5_unicode.rar' = '062c77fb1d47efbd5a468609a9c283ecb0b4cae43b0f6778935c41a975cedee9'
    'libarchive/test_read_format_rar5_win32.rar' = 'f33f17c7b3f1a623bba4f81b41565860ae9f1589dfaf7386e62a520543390c49'
    'libarchive/test_read_format_rar5_blake2.rar' = 'e2889c7498cb8065b9fd2338b142a135b906576a30d24acaf44850cca6fb845a'
    'libarchive/test_read_format_rar_multivolume.part0002.rar' = 'd1c3d9558671095c2876a958201fbcc6f5722f866ef9e2cf87d9913de82b31e1'
    'libarchive/test_read_format_rar_multivolume.part0003.rar' = '98872418a02ad45e09c93b08d8418981fa33c77bdbefcdd1f033de9371c5f96e'
    'libarchive/test_read_format_rar_multivolume.part0004.rar' = '229fb3c528593895f63c220843a0c4d2b88170407adc28f12b988e8f27695801'
    'libarchive/test_read_format_rar5_multiarchive_solid.part02.rar' = 'eb119ed53511905ca6f1844c164b6246d8fcdca0d1f38a8e3fb13da9c0932fbd'
    'libarchive/test_read_format_rar5_multiarchive_solid.part03.rar' = 'e814c3dbdaf3f613fd25c840065d25543f31e6b6c95505e7e25f47867a4812bd'
    'libarchive/test_read_format_rar5_multiarchive_solid.part04.rar' = '9ff5a4e633b0e82a2ce6e022f3d389654dbb77a0906a34f107676d6673989c9f'
    'libarchive/broken/test_read_format_rar5_bad_tables.rar' = 'a5368fced1d7e0740221699bac2ec2c7f53f6a0f87d6d6eec93ff7b5bb296554'
    'libarchive/broken/test_read_format_rar5_block_size_is_too_small.rar' = '50722e647132c1bc8e5cae346f35933069b551e6c405580c26f29929d82450ea'
    'libarchive/broken/test_read_format_rar5_decode_number_out_of_bounds_read.rar' = 'd019c3780fe660fc4be057bda4129ba3480f317d83e52c804b033c17a30c7b76'
    'libarchive/broken/test_read_format_rar5_distance_overflow.rar' = '65f8ef887536d4fad152f6d8dc1be54118cc2c1d9e7d3d325fdc4a219233da27'
    'libarchive/broken/test_read_format_rar5_invalid_dict_reference.rar' = '3c86264d0a80b9b4524be465a8a2dd9725c252aaf5284f9eb592aa9d4fad8123'
    'libarchive/broken/test_read_format_rar5_leftshift1.rar' = 'c7a18acb4f0bad082aefb3cb40a0234266f6f7946d46600e5e7bda944f43936a'
    'libarchive/broken/test_read_format_rar5_leftshift2.rar' = '22d583a17ac10f9cc0db31628f043c69cc012bbcd8b613726500c25bbfd9e2f2'
    'libarchive/broken/test_read_format_rar5_readtables_overflow.rar' = '5bf245d433e32409a1e4c943b7f2528ecda0305119a83ac7f0682cefcef0581a'
    'libarchive/broken/test_read_format_rar5_redir_overflow.rar' = '47f06fbd84d91d7a28a85dbc0df87fd462ef0d300bc47ef7b2314c91140fe56e'
    'libarchive/broken/test_read_format_rar5_truncated_huff.rar' = 'e0b828fb606b4b3844423e8c346e1f77f77bf271dc8794346900c7370d700291'
    'libarchive/broken/test_read_format_rar5_unpacked_size_exceeds_declared.rar' = '75eb12f9d431a7dea179ca5a23d003b1f4cecce0f77d82c3246cc6e0d480bfd6'
    'libarchive/broken/test_read_format_rar5_window_buf_and_size_desync.rar' = '1729c8c8b45afa219465fe84c3634d7667898ce7d1a7e402f0e2ed7dcac7be69'
    'libarchive/broken/test_read_format_rar_endarc_huge.rar' = '3c450b494747b9c302e33825204d56346fcc2bac92e5089089d91aa369374259'
    'libarchive/broken/test_read_format_rar_invalid1.rar' = 'f4de1dd1618c48ca91c8a0f0b0353cba7a26fd7182153de54ba83a8c7007e6fe'
    'libarchive/broken/test_read_format_rar_newsub_huge.rar' = '1a6058b85f1a8ab122c62cf0877de5aee4dc275cdc4ae07842463ce651322af1'
    'libarchive/broken/test_read_format_rar_noeof.rar' = 'b42c3bdfd96eac9c3ab336b04b3b65d01a26aca099de4fae2b7d77372b83b4cc'
    'libarchive/broken/test_read_format_rar_overflow.rar' = 'd80f10d57fb9dd578389b755668f0c84560090088b338036b2f6c7ece46e029a'
    'libarchive/broken/test_read_format_rar_ppmd_use_after_free.rar' = 'bf15290f29b3fcdc48018b52100cfa80b52dc04e978b2c5f54ee19237cb739ad'
    'libarchive/broken/test_read_format_rar_ppmd_use_after_free2.rar' = '80164bedbdec5b9b0841014a989a6d4d355d66fe118f60a0cb0134a5c316195f'
    'libarchive/broken/test_read_format_rar_symlink_huge.rar' = 'ce88dbf2ed0c33c81d32265214c9b1038766bf1b33bd51a9eaebc1b7a8e187d4'
    'libarchive/COPYING' = '30e556b3959e3985d66efefec5eaac51d4995053caa1d3cffe6eb916f146f229'
    'rars/header_rar300_password.rar' = 'f560d78873b44e05951aae16b6b92d654997a271d121c36689df460309de0e57'
    'rars/ext_time_rar420.rar' = '2ee63b6882b5d215ef496dad9d3035bd25251639a1afa7e6c3ff59450cf7a7a2'
    'rars/COPYING' = 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'
}

function Sha256([byte[]]$bytes) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

# uudecode: a "begin" line, then lines whose first character gives their length.
function Decode-Uu([string]$text) {
    $lines = $text -split "`r?`n"
    $i = 0
    while ($i -lt $lines.Length -and -not $lines[$i].StartsWith('begin ')) { $i++ }
    $buf = [IO.MemoryStream]::new()
    for ($i++; $i -lt $lines.Length -and $lines[$i] -ne 'end'; $i++) {
        $l = $lines[$i]
        if ($l.Length -eq 0) { continue }
        $n = ([int]$l[0] - 32) -band 63
        if ($n -eq 0) { continue }
        $bytes = [byte[]]::new([math]::Ceiling($n / 3) * 3)
        $k = 0
        for ($j = 1; $k -lt $n; $j += 4) {
            $c = [int[]]::new(4)
            for ($q = 0; $q -lt 4; $q++) {
                $c[$q] = if ($j + $q -lt $l.Length) { ([int]$l[$j + $q] - 32) -band 63 } else { 0 }
            }
            $bytes[$k++] = (($c[0] -shl 2) -bor ($c[1] -shr 4)) -band 255
            $bytes[$k++] = ((($c[1] -band 15) -shl 4) -bor ($c[2] -shr 2)) -band 255
            $bytes[$k++] = ((($c[2] -band 3) -shl 6) -bor $c[3]) -band 255
        }
        $buf.Write($bytes, 0, $n)
    }
    , $buf.ToArray()
}

$work = Join-Path ([IO.Path]::GetTempPath()) "beezip-rar-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory $work | Out-Null
$fetched = [ordered]@{}

function Save([string]$dir, [string]$name, [byte[]]$bytes) {
    $hash = Sha256 $bytes
    $key = "$dir/$name"
    if (-not $Record) {
        if (-not $sha256.ContainsKey($key)) { throw "no SHA-256 recorded for $key" }
        if ($sha256[$key] -ne $hash) { throw "$key has SHA-256 $hash, expected $($sha256[$key])" }
    }
    $fetched[$key] = $hash
    New-Item -ItemType Directory -Force (Join-Path $work $dir) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $work "$dir/$name"), $bytes)
}

# libarchive: the .uu files, and its COPYING.
$names = @($good.Keys) + @($parts.Values | ForEach-Object { $_ }) + $broken
foreach ($name in $names) {
    $dir = if ($broken -contains $name) { 'libarchive/broken' } else { 'libarchive' }
    $text = (Invoke-WebRequest "$base/libarchive/test/$name.uu").Content
    if ($text -is [byte[]]) { $text = [Text.Encoding]::Latin1.GetString($text) }
    Save $dir $name (Decode-Uu $text)
}
Save 'libarchive' 'COPYING' (Invoke-WebRequest "$base/COPYING").RawContentStream.ToArray()

# rars: from the published crate.
$crate = Join-Path $work 'rars.crate'
Invoke-WebRequest 'https://static.crates.io/crates/rars/rars-0.12.3.crate' -OutFile $crate
$unpacked = Join-Path $work 'rars-crate'
New-Item -ItemType Directory $unpacked | Out-Null
tar -xzf $crate -C $unpacked
if ($LASTEXITCODE -ne 0) { throw 'could not unpack the rars crate' }
foreach ($r in $rars.GetEnumerator()) {
    Save 'rars' $r.Key ([IO.File]::ReadAllBytes((Join-Path $unpacked "rars-0.12.3/$($r.Value[0])")))
}
Save 'rars' 'COPYING' ([IO.File]::ReadAllBytes((Join-Path $unpacked 'rars-0.12.3/COPYING')))

if ($Record) {
    '$sha256 = @{'
    foreach ($f in $fetched.GetEnumerator()) { "    '$($f.Key)' = '$($f.Value)'" }
    '}'
    Remove-Item -Recurse -Force $work
    return
}

# What 7-Zip says each archive holds.
function Expected([string]$path, $passwords) {
    $pw = @(if ($passwords) { "-p$($passwords[0])" })
    $list = & $sevenZip l -slt -sccUTF-8 @pw $path
    if ($LASTEXITCODE -ne 0) { throw "7z l $path failed" }
    $items = @()
    $cur = $null
    foreach ($line in ($list | Select-Object -Skip 1)) {
        if ($line -match '^Path = (.*)$') {
            if ($cur) { $items += , $cur }
            $cur = @{ Path = $Matches[1] }
        } elseif ($cur -and $line -match '^(\w[\w ]*) = (.*)$') {
            $cur[$Matches[1]] = $Matches[2]
        }
    }
    if ($cur) { $items += , $cur }
    # The first block is the archive itself.
    $items = $items | Where-Object { $_.ContainsKey('Attributes') -or $_.ContainsKey('Folder') }
    # One extraction per password, each into its own folder: 7-Zip leaves a file it failed to
    # decrypt behind, so a later pass mustn't overwrite an earlier good one. An entry takes the
    # first pass that didn't report it.
    $passes = @()
    foreach ($p in @(if ($passwords) { $passwords } else { , $null })) {
        $dest = Join-Path $work "x-$([Guid]::NewGuid().ToString('N'))"
        $args7 = @('x', '-y', '-sccUTF-8', "-o$dest") + @(if ($p) { "-p$p" }) + @($path)
        $log = & $sevenZip @args7 2>&1
        $failed = @($log | ForEach-Object { "$_" } | Where-Object { $_ -match '^ERROR: .* : (.+)$' } |
            ForEach-Object { ($_ -replace '^ERROR: .* : ', '') -replace '\\', '/' })
        $passes += , @{ dest = $dest; failed = $failed }
    }
    $entries = @()
    foreach ($it in $items) {
        $rel = $it.Path -replace '\\', '/'
        if ($it['Folder'] -eq '+') { continue }
        $link = if ($it.ContainsKey('Symbolic Link')) { $it['Symbolic Link'] } else { '' }
        $hard = if ($it.ContainsKey('Hard Link')) { $it['Hard Link'] } else { '' }
        $pass = $passes | Where-Object { $_.failed -notcontains $rel } | Select-Object -First 1
        # RAR 2.x-4 keep a Unix link's target in its data: 7-Zip shows `lrwxrwxrwx` and
        # extracts a real link.
        if (-not $link -and $it['Attributes'] -match '\sl[rwxsStT-]{9}') {
            $link = (Get-Item -Force (Join-Path $pass.dest $it.Path)).Target
        }
        if ($link) {
            $entries += [ordered]@{ path = $rel; kind = 'symlink'; target = ($link -replace '\\', '/') }
            continue
        }
        $source = if ($hard) { $hard -replace '\\', '/' } else { $rel }
        $pass = $passes | Where-Object { $_.failed -notcontains $source } | Select-Object -First 1
        if (-not $pass) { throw "no password extracts $rel from $path" }
        $bytes = [IO.File]::ReadAllBytes((Join-Path $pass.dest $source))
        $shown = if ($nameFixes.ContainsKey($rel)) { $nameFixes[$rel] } else { $rel }
        $entries += [ordered]@{ path = $shown; kind = 'file'; size = $bytes.Length; sha256 = Sha256 $bytes }
    }
    $hardlinks = @($items | Where-Object { $_.ContainsKey('Hard Link') -and $_['Hard Link'] }).Count
    @{ entries = $entries; hardlinks = $hardlinks }
}

$records = [Collections.Generic.List[object]]::new()
function Add-Rar([string]$dir, [string]$name, $passwords, [string]$producer, [string]$command, [string[]]$more = @()) {
    $path = Join-Path $work "$dir/$name"
    $expected = Expected $path $passwords
    $entries = $expected.entries
    $hard = $expected.hardlinks
    $links = @($entries | Where-Object { $_.kind -eq 'symlink' }).Count
    $fx = [ordered]@{
        file = "$dir/$name"; producer = $producer; command = $command; chain = 'rar'
        password = if ($passwords) { $passwords[0] } else { $null }
        utc_mtimes = $false; hardlinks = $hard; symlinks = $links
    }
    if ($passwords -and $passwords.Count -gt 1) { $fx.passwords = @($passwords) }
    $more = @($more | Where-Object { $_ })
    if ($more.Count -gt 0) { $fx.parts = @($more | ForEach-Object { "$dir/$_" }) }
    $fx.entries = $entries
    $records.Add($fx)
}
foreach ($g in $good.GetEnumerator()) {
    $more = if ($parts.ContainsKey($g.Key)) { $parts[$g.Key] } else { @() }
    Add-Rar 'libarchive' $g.Key $g.Value 'WinRAR, from libarchive 3.8.11''s tests' "libarchive/test/$($g.Key).uu at $tag, uudecoded" $more
}
foreach ($r in $rars.GetEnumerator()) {
    Add-Rar 'rars' $r.Key $r.Value[1] 'WinRAR, from rars 0.12.3''s tests' "rars-0.12.3/$($r.Value[0])"
}

# Copy into place, and merge the records into the manifest: this script owns libarchive/<name>
# and rars/; fetch-libarchive.ps1 owns libarchive/<fmt>/, delharc/ and packages/, make-linux.sh
# linux/, and make-thirdparty.ps1 the top-level names. Records it doesn't own are kept.
foreach ($dir in 'libarchive', 'libarchive/broken', 'rars') {
    $target = Join-Path $out $dir
    New-Item -ItemType Directory -Force $target | Out-Null
    Get-ChildItem $target -File | Remove-Item -Force
    Get-ChildItem (Join-Path $work $dir) -File | Copy-Item -Destination $target
}
$manifestPath = Join-Path $PSScriptRoot 'manifest.json'
$manifest = Get-Content -Raw $manifestPath | ConvertFrom-Json -AsHashtable
$mine = { param($file) ($file -like 'libarchive/*' -and $file -notlike 'libarchive/*/*') -or $file -like 'rars/*' }
# The new records go where the old ones were, so a rerun leaves the order alone.
$old = @($manifest.fixtures)
$at = 0
while ($at -lt $old.Count -and -not (& $mine $old[$at].file)) { $at++ }
$before = @(if ($at -gt 0) { $old[0..($at - 1)] })
$after = @($old | Select-Object -Skip $at | Where-Object { -not (& $mine $_.file) })
$manifest.fixtures = $before + $records + $after
($manifest | ConvertTo-Json -Depth 6) -replace "`r`n", "`n" | Set-Content -NoNewline $manifestPath
Remove-Item -Recurse -Force $work
$size = (Get-ChildItem -Recurse -File (Join-Path $out 'libarchive'), (Join-Path $out 'rars') | Measure-Object Length -Sum).Sum
"fetched $($fetched.Count) files ($([math]::Round($size / 1KB)) KiB), $($records.Count) in the manifest"
