#!/bin/bash
# Makes tests/fixtures/thirdparty/7zip/ and three files of tests/fixtures/malicious/ for the 7-Zip
# backend (docs/M6.md §3, §10): file-system images, partitioned disks, virtual disks, WIM, NSIS,
# CHM and MSI, each small, from one seeded tree; then merges their records into manifest.json.
# Run it from Windows, in the repository, with Docker Desktop running:
#
#   wsl -e bash tests/fixtures/make-7z.sh
#
# The images are made in a container (make-7z.Dockerfile, built here as beezip-fixtures-7z), which
# runs this script again with --inside; it needs FUSE for ntfs-3g:
#   docker run --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor=unconfined
# Tools (Ubuntu 24.04's packages, 2026-11-07): mke2fs and debugfs 1.47.0 (e2fsprogs), mkfs.fat
# 4.2 and mtools 4.0.43, mkntfs and ntfs-3g 2022.10.3, mkfs.cramfs 2.39.3 (util-linux), sfdisk
# 2.39.3, qemu-img 8.2.2, wimlib 1.14.4, makensis 3.09, wixl 0.103, chmcmd 3.2.2 (Free Pascal),
# libfaketime 0.9.10, python3 3.12. Then, in WSL: Windows' 7-Zip 26.00 through WSL's interop makes
# tree.wim (`7z a -twim`), takes the bare HFS+ and APFS volumes out of the committed hdiutil DMGs
# (thirdparty/dmg/, made by make-dmg.sh on macOS; `7z e -tdmg`), and lists, extracts and tests
# every image for its record.
#
# The tree: text, an empty file, 64 KiB of pseudo-random bytes (Python's Random(42)), nested
# folders, names in CJK, an emoji, accents and a space, a folder with a non-ASCII name, a symlink,
# a symlink to a folder and a hard link, every time 2026-01-01T00:00:00Z but mtime.txt's,
# 2024-05-06T07:08:09.123456789Z. Each file system holds what it can of it (FAT has no links:
# mcopy copies the file symlink and skips the folder one).
#
# Deterministic: a rerun writes the same bytes (checked by running it twice), with fixed ids and
# times: mke2fs -U and -E hash_seed, with E2FSPROGS_FAKE_TIME, and debugfs setting the change times
# mke2fs copies from the source tree; mkfs.fat --invariant -i, and mtools with SOURCE_DATE_EPOCH;
# mkntfs and ntfs-3g under a frozen libfaketime clock; sfdisk's label-id and partition uuids;
# mkfs.cramfs as it is; qemu-img, wimlib, makensis and wixl under the frozen clock. What the tools
# draw at random, or take from a clock libfaketime can't reach, is fixed afterwards: the WIM GUID
# (wimlib's and 7-Zip's) and 7-Zip's XML times; the VDI, VHD and VHDX ids, with the checksums over
# them, and the VHDX's sequence numbers and stale log; VMDK's CID; the MSI's package code; chmcmd's
# time stamps (Free Pascal makes its own system calls). tree.wim depends on Windows' 7-Zip too.
#
# Expected entries are what 7-Zip 26.00 lists (`7z l -slt -sccUTF-8 -scsUTF-8 -slmu -slsl -sns-`),
# pseudo entries included, and the bytes `7z x -sns-` extracts, checked against the source tree
# where an image holds it (the DMG volumes against the DMGs' records). Each record notes what 7-Zip
# does that a reader of it should know.
set -euo pipefail

E=1767225600 # 2026-01-01T00:00:00Z
faked=(env LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME='2026-01-01 00:00:00'
    NO_FAKE_STAT=1)

# ---------------------------------------------------------------------------------------------
# In the container (root): the images, into /out/7zip and /out/malicious; the tree as /out/tree.tar.
if [ "${1:-}" = --inside ]; then
    export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC SOURCE_DATE_EPOCH=$E
    out=/out/7zip
    mal=/out/malicious
    mkdir -p "$out" "$mal" /work
    # noatime, so reading the tree leaves its access times alone.
    mount -t tmpfs -o noatime,size=1g tmpfs /work
    cd /work

    T=/work/tree
    mkdir -p "$T/sub/nested" "$T/Ünïcödé dir"
    printf 'Hello, BeeZip!\n' > "$T/readme.txt"
    : > "$T/empty.txt"
    python3 -I -c 'import random, sys; sys.stdout.buffer.write(random.Random(42).randbytes(65536))' > "$T/random.bin"
    printf 'known mtime\n' > "$T/mtime.txt"
    printf 'CJK\n' > "$T/名前.txt"
    printf 'emoji\n' > "$T/bee-🐝.txt"
    printf 'accents\n' > "$T/café-ñandú.txt"
    printf 'a space\n' > "$T/with space.txt"
    printf 'deep\n' > "$T/sub/nested/deep.txt"
    printf 'non-ASCII folder\n' > "$T/Ünïcödé dir/日本語.txt"
    ln -s readme.txt "$T/link-to-readme"
    ln -s nested "$T/sub/link-to-nested"
    ln "$T/readme.txt" "$T/hard-readme.txt"
    find "$T" -exec touch -h -d "@$E" {} +
    touch -d '2024-05-06 07:08:09.123456789 UTC' "$T/mtime.txt"
    tar --format=posix --sort=name -C /work -cf /out/tree.tar tree

    # ext: mke2fs copies each file's change time from the tree (which touch can't set) and drops
    # every nanosecond; debugfs gives every inode reachable from the root the fixed change time, and
    # mtime.txt its nanoseconds where the inode has room for them.
    export E2FSPROGS_FAKE_TIME=$E
    ext_fix() { # image [path nanoseconds]
        python3 -I - "$1" "$E" "${2:-}" "${3:-}" <<'PY'
import re, subprocess, sys
img, e, path, ns = sys.argv[1:5]
# Every inode reachable from the root, from `ls -l <inode>` of each folder (a name with a newline
# in it runs onto lines that don't start with an inode number).
seen, todo = {2}, [2]
while todo:
    listing = subprocess.run(['debugfs', '-R', f'ls -l <{todo.pop()}>', img], capture_output=True, check=True)
    for line in listing.stdout.decode('utf-8', 'replace').split('\n'):
        m = re.match(r'^\s*(\d+)\s+(\d+) \(\d+\)', line)
        if m and int(m.group(1)) not in seen:
            seen.add(int(m.group(1)))
            if int(m.group(2), 8) & 0o170000 == 0o040000:
                todo.append(int(m.group(1)))
cmds = [f'sif <{i}> ctime @{e}' for i in sorted(seen)]
if path:
    cmds.append(f'sif {path} mtime_extra {int(ns) << 2}')
subprocess.run(['debugfs', '-w', '-f', '-', img], input='\n'.join(cmds).encode(), capture_output=True, check=True)
PY
    }
    u() { printf '6d7a6970-6265-457a-8970-%012x' "$1"; } # fixed UUIDs, numbered
    # ext4 with its journal (1 MiB, the least mke2fs makes), and 256-byte inodes, which hold
    # nanoseconds; ext2 with 128-byte inodes, which don't.
    mke2fs -q -t ext4 -b 1024 -I 256 -U "$(u 1)" -E "hash_seed=$(u 1),root_owner=0:0" -L BeeZipExt4 \
        -d "$T" "$out/ext4.img" 2M
    ext_fix "$out/ext4.img" /mtime.txt 123456789
    mke2fs -q -t ext2 -b 1024 -I 128 -U "$(u 2)" -E "hash_seed=$(u 2),root_owner=0:0" -L BeeZipExt2 \
        -d "$T" "$out/ext2.img" 256K
    ext_fix "$out/ext2.img"
    # The GPT disk's ext4, without a journal, to keep the disk and its virtual disks small.
    mke2fs -q -t ext4 -O ^has_journal -b 1024 -I 256 -N 64 -U "$(u 5)" -E "hash_seed=$(u 5),root_owner=0:0" \
        -L BeeZipGPT -d "$T" /work/gpt-ext4.img 384K
    ext_fix /work/gpt-ext4.img /mtime.txt 123456789

    # FAT: mcopy copies the file symlink as a file and skips the folder one.
    export MTOOLS_SKIP_CHECK=1
    mkfs.fat --invariant -F 12 -i 6D7A6970 -n BEEZIPFAT12 -C "$out/fat12.img" 256 >/dev/null
    mcopy -s -p -m -i "$out/fat12.img" "$T"/* ::/ 2>/dev/null
    # FAT32 in 1 MiB, with fewer clusters than the 65 525 the specification asks of FAT32
    # (mkfs.fat warns); its BIOS parameter block says FAT32, which is what 7-Zip goes by.
    mkfs.fat --invariant -F 32 -i 6D7A6970 -n BEEZIPFAT32 -C "$out/fat32.img" 1024 >/dev/null 2>&1
    mcopy -s -p -m -i "$out/fat32.img" "$T"/* ::/ 2>/dev/null

    # NTFS through ntfs-3g (FUSE), under a frozen clock: hard links, symlinks as NTFS symlink
    # reparse points (ntfs-3g makes Interix links itself, which 7-Zip lists as plain files), and
    # an alternate data stream on readme.txt.
    truncate -s 1280K "$out/ntfs.img"
    "${faked[@]}" mkntfs -q -F -Q -s 512 -p 0 -H 255 -S 63 -L BeeZipNTFS "$out/ntfs.img" >/dev/null 2>&1
    mkdir -p /mnt/ntfs
    "${faked[@]}" ntfs-3g -o streams_interface=windows,no_detach "$out/ntfs.img" /mnt/ntfs &
    ntfs=$!
    for _ in $(seq 100); do
        mountpoint -q /mnt/ntfs && break
        kill -0 "$ntfs" && sleep 0.1
    done
    mountpoint -q /mnt/ntfs
    cp -a "$T"/. /mnt/ntfs/
    rm /mnt/ntfs/link-to-readme /mnt/ntfs/sub/link-to-nested
    python3 -I - /mnt/ntfs <<'PY'
import os, struct, sys
root = sys.argv[1]
def symlink(path, target, folder):
    # IO_REPARSE_TAG_SYMLINK: the substitute and print names' offsets and lengths, the flags
    # (relative), then the names.
    name = target.encode('utf-16-le')
    body = struct.pack('<HHHHI', 0, len(name), len(name), len(name), 1) + name + name
    data = struct.pack('<IHH', 0xA000000C, len(body), 0) + body
    if folder:
        os.mkdir(path)
    else:
        open(path, 'wb').close()
    os.setxattr(path, 'system.ntfs_reparse_data', data)
symlink(os.path.join(root, 'link-to-readme'), 'readme.txt', False)
symlink(os.path.join(root, 'sub', 'link-to-nested'), 'nested', True)
PY
    printf 'an alternate stream\n' > /mnt/ntfs/readme.txt:hidden
    umount /mnt/ntfs
    wait "$ntfs"

    mkfs.cramfs -n BeeZipCramfs "$T" "$out/cramfs.img" >/dev/null

    # Disks: an MBR holding the FAT12 volume; a GPT holding FAT12 and ext4; a GPT holding NTFS.
    # Partitions start at sector 64; the volumes are fat12.img, ntfs.img and the journal-less
    # ext4 above, byte for byte.
    sectors() { echo $(($(stat -c %s "$1") / 512)); }
    fat=$(sectors "$out/fat12.img")
    truncate -s $(((64 + fat) * 512)) "$out/mbr-fat.img"
    printf 'label: dos\nlabel-id: 0x6d7a6970\nunit: sectors\n\nstart=64, size=%d, type=1\n' "$fat" |
        sfdisk -q "$out/mbr-fat.img"
    dd if="$out/fat12.img" of="$out/mbr-fat.img" bs=512 seek=64 conv=notrunc status=none
    gpt() { # disk, then "image type name" per partition
        local disk=$1 at=64 n=0 script img type name
        shift
        script="label: gpt\nlabel-id: $(u 100)\nunit: sectors\nfirst-lba: 34\n\n"
        for p in "$@"; do
            read -r img type name <<< "$p"
            n=$((n + 1))
            script+="start=$at, size=$(sectors "$img"), type=$type, uuid=$(u $((100 + n))), name=\"$name\"\n"
            at=$((at + $(sectors "$img")))
        done
        # The backup table's 33 sectors, rounded up to 4 KiB: 7-Zip 26.00 can't open a VHDX of a
        # disk that's an odd number of sectors.
        truncate -s $(((at + 33 + 7) / 8 * 4096)) "$disk"
        printf "$script" | sfdisk -q "$disk"
        at=64
        for p in "$@"; do
            read -r img type name <<< "$p"
            dd if="$img" of="$disk" bs=512 seek=$at conv=notrunc status=none
            at=$((at + $(sectors "$img")))
        done
    }
    basic=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
    linux=0FC63DAF-8483-4772-8E79-3D69D8477DE4
    gpt "$out/gpt-fat-ext4.img" "$out/fat12.img $basic data" "/work/gpt-ext4.img $linux linux"
    gpt "$out/gpt-ntfs.img" "$out/ntfs.img $basic ntfs"

    # Virtual disks of them, with qemu-img under the frozen clock (VHD's footer holds the time).
    q() { "${faked[@]}" qemu-img convert -f raw "$@"; }
    q -O qcow2 "$out/gpt-fat-ext4.img" "$out/gpt-fat-ext4.qcow2"
    q -O vdi "$out/gpt-fat-ext4.img" "$out/gpt-fat-ext4.vdi"
    q -O vmdk -o subformat=monolithicSparse "$out/gpt-fat-ext4.img" "$out/gpt-fat-ext4.vmdk"
    q -O vpc -o subformat=dynamic,force_size=on "$out/mbr-fat.img" "$out/mbr-fat.vhd"
    q -O vpc -o subformat=fixed,force_size=on "$out/mbr-fat.img" "$out/mbr-fat-fixed.vhd"
    q -O vhdx -o block_size=1M,log_size=1M "$out/gpt-ntfs.img" "$out/gpt-ntfs.vhdx"

    # WIM and ESD through wimlib: LZX with two images (the tree, then its sub folder), and solid
    # LZMS as an .esd.
    "${faked[@]}" wimcapture "$T" "$out/wimlib.wim" BeeZip --compress=lzx >/dev/null
    "${faked[@]}" wimappend "$T/sub" "$out/wimlib.wim" Sub >/dev/null
    "${faked[@]}" wimcapture "$T" "$out/wimlib-solid.esd" BeeZip --solid >/dev/null

    # NSIS installers of the tree's files, in each compressor.
    mkdir -p /work/nsis
    for comp in lzma zlib bzip2; do
        solid=
        [ "$comp" = lzma ] && solid=/SOLID
        sed -e "s|@COMP@|$solid $comp|" -e "s|@OUT@|$out/nsis-$comp.exe|" -e "s|@T@|$T|g" \
            > "/work/nsis/$comp.nsi" <<'NSI'
Unicode true
Name "BeeZip fixture"
OutFile "@OUT@"
SetCompressor @COMP@
InstallDir "$LOCALAPPDATA\BeeZip fixture"
RequestExecutionLevel user
Section
  SetOutPath "$INSTDIR"
  File "@T@/readme.txt"
  File "@T@/hard-readme.txt"
  File "@T@/empty.txt"
  File "@T@/random.bin"
  File "@T@/mtime.txt"
  File "@T@/名前.txt"
  File "@T@/bee-🐝.txt"
  File "@T@/café-ñandú.txt"
  File "@T@/with space.txt"
  SetOutPath "$INSTDIR\sub\nested"
  File "@T@/sub/nested/deep.txt"
  SetOutPath "$INSTDIR\Ünïcödé dir"
  File "@T@/Ünïcödé dir/日本語.txt"
SectionEnd
NSI
        "${faked[@]}" makensis -V1 -INPUTCHARSET UTF8 "/work/nsis/$comp.nsi" >/dev/null
    done

    # CHM through chmcmd.
    C=/work/chm
    mkdir -p "$C/pages"
    printf '<html><head><title>BeeZip</title></head><body><a href="pages/a.htm">a</a></body></html>\n' > "$C/index.htm"
    printf '<html><body>page a</body></html>\n' > "$C/pages/a.htm"
    printf '<html><body>café</body></html>\n' > "$C/pages/café.htm"
    printf '[OPTIONS]\nCompiled file=fixture.chm\nDefault topic=index.htm\nTitle=BeeZip fixture\n\n[FILES]\nindex.htm\npages/a.htm\npages/café.htm\n' > "$C/fixture.hhp"
    find "$C" -exec touch -h -d "@$E" {} +
    (cd "$C" && "${faked[@]}" chmcmd fixture.hhp >/dev/null)
    cp "$C/fixture.chm" "$out/chmcmd.chm"

    # MSI through wixl, with fixed product and package codes.
    M=/work/msi
    mkdir -p "$M"
    cp -p "$T/readme.txt" "$T/empty.txt" "$T/random.bin" "$M/"
    cp -p "$T/名前.txt" "$M/cjk.txt"
    cat > "$M/fixture.wxs" <<'WXS'
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="6D7A6970-6265-457A-8970-000000000201" Name="BeeZip fixture" Language="1033"
           Version="1.0.0" Manufacturer="BeeZip" UpgradeCode="6D7A6970-6265-457A-8970-000000000202"
           Codepage="65001">
    <Package Id="6D7A6970-6265-457A-8970-000000000203" InstallerVersion="200" Compressed="yes"
             InstallScope="perUser" />
    <Media Id="1" Cabinet="data.cab" EmbedCab="yes" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="LocalAppDataFolder">
        <Directory Id="INSTALLDIR" Name="BeeZip fixture">
          <Component Id="files" Guid="6D7A6970-6265-457A-8970-000000000204">
            <File Id="readme" Source="readme.txt" Name="readme.txt" KeyPath="yes" />
            <File Id="empty" Source="empty.txt" Name="empty.txt" />
            <File Id="random" Source="random.bin" Name="random.bin" />
            <File Id="cjk" Source="cjk.txt" Name="名前.txt" />
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="all" Level="1"><ComponentRef Id="files" /></Feature>
  </Product>
</Wix>
WXS
    (cd "$M" && "${faked[@]}" wixl -o "$out/wixl.msi" fixture.wxs)

    # The ids and times the tools above draw at random or take from a clock libfaketime doesn't
    # reach (chmcmd is Free Pascal, which makes its own system calls), fixed, and the checksums
    # over them redone; qemu-img checks the virtual disks afterwards.
    python3 -I - "$out" <<'PY'
import os, re, struct, sys, uuid
out = sys.argv[1]
def fixed(n):
    return uuid.UUID(f'6d7a6970-6265-457a-8970-{n:012x}')
def patch(name, edits):
    path = os.path.join(out, name)
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    edits(data)
    with open(path, 'wb') as f:
        f.write(data)
def chm(data):
    # The ITSF header's time stamp, and #SYSTEM's (code 10).
    data[16:20] = bytes(4)
    m = re.search(rb'\n\x00\x04\x00(.{4})\t\x00', data, re.S)
    data[m.start(1):m.end(1)] = bytes(4)
def msi(data):
    # The package code, which wixl draws whatever the Package element says (the summary
    # information's revision number).
    for m in re.finditer(rb'\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}', bytes(data)):
        if not m.group().startswith(b'{6D7A6970-'):
            data[m.start():m.end()] = b'{%s}' % str(fixed(0x203)).upper().encode()
def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 & -(crc & 1))
    return crc ^ 0xFFFFFFFF
def wim(data):
    # The header's GUID.
    data[24:40] = fixed(0x300).bytes_le
def vdi(data):
    # uuidCreate and uuidModify; the linkage and parent UUIDs stay zero.
    data[0x188:0x198] = fixed(0x301).bytes_le
    data[0x198:0x1a8] = fixed(0x302).bytes_le
def vhd(data):
    # The footer's unique id and checksum, in the footer and (dynamic) its copy at the start.
    for at in {0, len(data) - 512}:
        if data[at:at + 8] != b'conectix':
            continue
        data[at + 0x44:at + 0x54] = fixed(0x303).bytes
        data[at + 0x40:at + 0x44] = bytes(4)
        data[at + 0x40:at + 0x44] = struct.pack('>I', ~sum(data[at:at + 512]) & 0xFFFFFFFF)
def vmdk(data):
    # The descriptor's content id.
    m = re.search(rb'\nCID=([0-9a-f]+)\n', data)
    data[m.start(1):m.end(1)] = b'6d7a6970'[:m.end(1) - m.start(1)].rjust(m.end(1) - m.start(1), b'0')
def vhdx(data):
    # The regions (BAT and metadata) and the metadata items (block size, the disk's id).
    regions = 192 << 10
    assert data[regions:regions + 4] == b'regi'
    region = {}
    for i in range(struct.unpack_from('<I', data, regions + 8)[0]):
        e = regions + 16 + 32 * i
        region[uuid.UUID(bytes_le=bytes(data[e:e + 16]))] = struct.unpack_from('<QI', data, e + 16)
    bat, bat_len = region[uuid.UUID('2DC27766-F623-4200-9D64-115E9BFD4A08')]
    meta, meta_len = region[uuid.UUID('8B7CA206-4790-4B9A-B8FE-575F050F886E')]
    assert data[meta:meta + 8] == b'metadata'
    item = {}
    for i in range(struct.unpack_from('<H', data, meta + 10)[0]):
        e = meta + 32 + 32 * i
        item[uuid.UUID(bytes_le=bytes(data[e:e + 16]))] = meta + struct.unpack_from('<I', data, e + 16)[0]
    block = struct.unpack_from('<I', data, item[uuid.UUID('CAA16737-FA36-4D43-B3B6-33F0AA44E76B')])[0]
    disk_id = item[uuid.UUID('BECA12AB-B2E6-4523-93EF-C309E000C746')]
    data[disk_id:disk_id + 16] = fixed(0x307).bytes_le
    # The headers: fixed file-write and data-write GUIDs, sequence numbers 1 and 2 in the order
    # qemu-img left them (it starts from a random one), the log empty (its GUID zero), CRC-32C.
    heads = (64 << 10, 128 << 10)
    seqs = sorted(heads, key=lambda at: struct.unpack_from('<Q', data, at + 8)[0])
    for at in heads:
        assert data[at:at + 4] == b'head' and not any(data[at + 48:at + 64])
        log_len, log = struct.unpack_from('<IQ', data, at + 68)
        data[at + 8:at + 16] = struct.pack('<Q', seqs.index(at) + 1)
        data[at + 16:at + 32] = fixed(0x304).bytes_le
        data[at + 32:at + 48] = fixed(0x305).bytes_le
        data[at + 4:at + 8] = bytes(4)
        data[at + 4:at + 8] = struct.pack('<I', crc32c(data[at:at + 4096]))
    # An empty log's entries are never read: zero the ones qemu-img wrote (they hold its random
    # log GUID).
    data[log:log + log_len] = bytes(log_len)
    # qemu-img puts the first payload block at 8 MiB; move the blocks down to the end of the
    # regions (each stays 1 MiB-aligned) and cut the file there.
    at = max(bat + bat_len, meta + meta_len)
    blocks = bytearray()
    for i in range(bat_len // 8):
        entry = struct.unpack_from('<Q', data, bat + 8 * i)[0]
        if entry & 7 in (6, 7): # fully or partly present
            src = entry >> 20 << 20
            struct.pack_into('<Q', data, bat + 8 * i, (at + len(blocks)) | entry & 7)
            blocks += data[src:src + block]
    del data[at:]
    data += blocks
for name in ('wimlib.wim', 'wimlib-solid.esd'):
    patch(name, wim)
patch('gpt-fat-ext4.vdi', vdi)
patch('mbr-fat.vhd', vhd)
patch('mbr-fat-fixed.vhd', vhd)
patch('gpt-fat-ext4.vmdk', vmdk)
patch('gpt-ntfs.vhdx', vhdx)
patch('chmcmd.chm', chm)
patch('wixl.msi', msi)
PY
    for f in gpt-fat-ext4.qcow2 gpt-fat-ext4.vdi gpt-fat-ext4.vmdk gpt-ntfs.vhdx; do
        qemu-img check -q "$out/$f"
    done
    for f in "gpt-fat-ext4.qcow2 qcow2 gpt-fat-ext4.img" "gpt-fat-ext4.vdi vdi gpt-fat-ext4.img" \
        "gpt-fat-ext4.vmdk vmdk gpt-fat-ext4.img" "mbr-fat.vhd vpc mbr-fat.img" \
        "mbr-fat-fixed.vhd vpc mbr-fat.img" "gpt-ntfs.vhdx vhdx gpt-ntfs.img"; do
        read -r disk format raw <<< "$f"
        qemu-img compare -q -f raw -F "$format" "$out/$raw" "$out/$disk"
    done
    mkdir -p /out/parts
    cp /work/gpt-ext4.img /out/parts/

    # ---- The malicious images. ----
    # Names and links that must not be trusted: ext allows any byte in a name but `/` and NUL.
    H=/work/hostile
    mkdir -p "$H/dir" "$H/C:" "$H/.. "
    printf 'safe\n' > "$H/safe.txt"
    printf 'inside\n' > "$H/dir/inside.txt"
    printf 'dots\n' > "$H/..."
    printf 'dot-dot-space\n' > "$H/.. /escape.txt"
    printf 'backslashes\n' > "$H/..\\..\\escape.txt"
    printf 'drive\n' > "$H/C:/drive.txt"
    printf 'colon\n' > "$H/ads:stream.txt"
    printf 'device name\n' > "$H/CON"
    printf 'device name\n' > "$H/aux.txt"
    printf 'trailing dot\n' > "$H/trail."
    printf 'trailing space\n' > "$H/trail "
    printf 'carriage return\n' > "$H/$(printf 'cr\rname.txt')"
    printf 'forged\n' > "$H/$(printf 'x\n\nPath = forged..\\..\\out.txt\nFolder = -\nSize = 5')"
    printf 'not UTF-8\n' > "$H/$(printf 'bad\xff\xfe.txt')"
    ln -s ../../outside.txt "$H/link-rel"
    ln -s /etc/passwd "$H/link-abs"
    ln -s 'C:\Windows\win.ini' "$H/link-drive"
    ln -s //server/share/x "$H/link-unc"
    ln -s ../.. "$H/link-up"
    ln -s dir "$H/link-dir"
    mknod "$H/null" c 1 3
    mkfifo "$H/fifo"
    find "$H" -exec touch -h -d "@$E" {} +
    mke2fs -q -t ext4 -O ^has_journal -b 1024 -I 256 -N 64 -U "$(u 3)" -E "hash_seed=$(u 3),root_owner=0:0" \
        -L BeeZipHostile -d "$H" "$mal/ext4-hostile.img" 256K
    ext_fix "$mal/ext4-hostile.img"

    # One sparse file of 100 GB (107 374 182 400 bytes) in a 256 KiB image.
    S=/work/sparse
    mkdir -p "$S"
    printf 'safe\n' > "$S/safe.txt"
    truncate -s 100G "$S/sparse.bin"
    printf 'start\n' | dd of="$S/sparse.bin" conv=notrunc status=none
    printf 'end\n' | dd of="$S/sparse.bin" bs=1 seek=$((107374182400 - 4)) conv=notrunc status=none
    find "$S" -exec touch -h -d "@$E" {} +
    mke2fs -q -t ext4 -O ^has_journal -b 1024 -I 256 -N 64 -U "$(u 4)" -E "hash_seed=$(u 4),root_owner=0:0" \
        -L BeeZipSparse -d "$S" "$mal/ext4-sparse-100g.img" 256K
    ext_fix "$mal/ext4-sparse-100g.img"

    # A WIM whose symlinks (reparse points) lead out, stored as they are (--norpfix).
    W=/work/wimlinks
    mkdir -p "$W/dir"
    printf 'safe\n' > "$W/safe.txt"
    printf 'inside\n' > "$W/dir/inside.txt"
    ln -s ../../outside.txt "$W/link-rel"
    ln -s /etc/passwd "$W/link-abs"
    ln -s ../.. "$W/link-up"
    ln -s dir "$W/link-dir"
    find "$W" -exec touch -h -d "@$E" {} +
    "${faked[@]}" wimcapture "$W" "$mal/wim-links-out.wim" Links --norpfix >/dev/null
    python3 -I -c '
import sys, uuid
with open(sys.argv[1], "r+b") as f:
    f.seek(24)
    f.write(uuid.UUID("6d7a6970-6265-457a-8970-000000000308").bytes_le)' "$mal/wim-links-out.wim"

    dpkg-query -W -f '${Package} ${Version}\n' e2fsprogs dosfstools mtools ntfs-3g util-linux-extra fdisk \
        qemu-utils wimtools nsis wixl fp-utils-3.2.2 libfaketime > /out/versions.txt
    chown -R "${HOST_IDS:-0:0}" /out
    cd / && umount /work
    exit 0
fi

# ---------------------------------------------------------------------------------------------
# In WSL.
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/thirdparty/7zip"
seven='/mnt/c/Program Files/7-Zip/7z.exe'
command -v docker python3 wslpath >/dev/null
[ -x "$seven" ] || { echo "no 7-Zip at $seven" >&2; exit 1; }
work="$(mktemp -d)"
wintemp="$(wslpath -u "$(cd /mnt/c && cmd.exe /c 'echo %TEMP%' 2>/dev/null | tr -d '\r')")"
win="$(mktemp -d -p "$wintemp" beezip-7z.XXXXXX)"
trap 'rm -rf "$work" "$win"' EXIT

docker build -q -t beezip-fixtures-7z - < "$here/make-7z.Dockerfile" >/dev/null
made="$work/made"
mkdir -p "$made"
docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
    -e HOST_IDS="$(id -u):$(id -g)" -v "$here/make-7z.sh:/make-7z.sh:ro" -v "$made:/out" \
    beezip-fixtures-7z bash /make-7z.sh --inside

# tree.wim from Windows' 7-Zip: the tree on NTFS (no symlinks, which Windows makes only in
# Developer Mode or as an administrator; the hard link as a copy). WSL's drvfs drops the fraction
# of a second from the times it sets, so Windows PowerShell sets them, to 100 ns.
mkdir -p "$win/tree"
python3 -I - "$made/tree.tar" "$win/tree" "$(wslpath -w "$win/tree")" "$win/times" <<'PY'
import os, shutil, sys, tarfile
from decimal import Decimal
src, dest, windest, times_path = sys.argv[1:5]
times = []
with tarfile.open(src) as t:
    for m in t.getmembers():
        rel = m.name.split('/', 1)[1] if '/' in m.name else ''
        path = os.path.join(dest, rel)
        if m.isdir():
            os.makedirs(path, exist_ok=True)
        elif m.isfile():
            with open(path, 'wb') as f:
                shutil.copyfileobj(t.extractfile(m), f)
        elif m.islnk():
            shutil.copyfile(os.path.join(dest, m.linkname.split('/', 1)[1]), path)
        else:
            continue
        ticks = 621355968000000000 + int(Decimal(m.pax_headers.get('mtime', m.mtime)) * 10**7)
        times.append((windest + ('\\' + rel.replace('/', '\\') if rel else ''), ticks))
with open(times_path + '.tsv', 'w', encoding='utf-8', newline='\n') as f:
    for path, ticks in sorted(times, key=lambda x: -len(x[0])):
        f.write(f'{path}\t{ticks}\n')
with open(times_path + '.ps1', 'w', encoding='utf-8-sig', newline='\n') as f:
    f.write('''param([string]$List)
foreach ($line in [IO.File]::ReadAllLines($List, [Text.Encoding]::UTF8)) {
    $path, $ticks = $line.Split("`t")
    $t = [DateTime]::new([long]$ticks, [DateTimeKind]::Utc)
    $kind = if ([IO.Directory]::Exists($path)) { [IO.Directory] } else { [IO.File] }
    $kind::SetCreationTimeUtc($path, $t)
    $kind::SetLastWriteTimeUtc($path, $t)
    $kind::SetLastAccessTimeUtc($path, $t)
}
''')
PY
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w "$win/times.ps1")" "$(wslpath -w "$win/times.tsv")"
(cd "$win/tree" && "$seven" a -twim -bso0 -bsp0 ../tree.wim '*')
# 7-Zip draws the WIM's GUID at random and stamps its XML with the time it was made: fixed, as
# wimlib's are above (the XML has no checksum).
python3 -I - "$win/tree.wim" <<'PY'
import re, sys, uuid
with open(sys.argv[1], 'r+b') as f:
    data = bytearray(f.read())
    data[24:40] = uuid.UUID('6d7a6970-6265-457a-8970-000000000309').bytes_le
    # The XML (UTF-16LE, after a BOM) runs to the end of the file.
    at = data.index('﻿<WIM>'.encode('utf-16-le'))
    xml = data[at:].decode('utf-16-le')
    fixed = re.sub(r'<HIGHPART>0x[0-9A-F]{8}</HIGHPART><LOWPART>0x[0-9A-F]{8}</LOWPART>',
                   '<HIGHPART>0x01DC7AB1</HIGHPART><LOWPART>0x92810000</LOWPART>', xml) # 2026-01-01
    assert len(fixed) == len(xml) and fixed != xml
    data[at:] = fixed.encode('utf-16-le')
    f.seek(0)
    f.write(data)
PY
cp "$win/tree.wim" "$made/7zip/tree.wim"

# HFS+ and APFS volumes as they are in two of the DMGs make-dmg.sh made on macOS.
mkdir -p "$win/dmg"
for v in "hfs-udro.dmg 4.hfs dmg-hfs.hfs" "apfs-udro.dmg 4.apfs dmg-apfs.apfs"; do
    set -- $v
    "$seven" e -tdmg -bso0 -bsp0 -o"$(wslpath -w "$win/dmg")" -- "$(wslpath -w "$here/thirdparty/dmg/$1")" "$2"
    cp "$win/dmg/$2" "$made/7zip/$3"
done

mkdir -p "$out"
find "$out" -maxdepth 1 -type f -delete
cp "$made"/7zip/* "$out/"
for f in ext4-hostile.img ext4-sparse-100g.img wim-links-out.wim; do
    cp "$made/malicious/$f" "$here/malicious/$f"
done

# The records, merged into manifest.json (this script owns 7zip/), and the README.
python3 -I -B - "$here" "$made" "$seven" "$win" <<'PY'
import hashlib, json, os, re, subprocess, sys, tarfile, tempfile, unicodedata
here, made, seven, win = sys.argv[1:5]
out = os.path.join(here, 'thirdparty', '7zip')
mal = os.path.join(here, 'malicious')

versions = dict(l.split(' ', 1) for l in open(os.path.join(made, 'versions.txt')).read().splitlines())
def ver(pkg):
    return re.match(r'(?:\d+:)?(\d+(?:\.\d+)*)', versions[pkg]).group(1)
docker = 'Ubuntu 24.04 in Docker'
PRODUCER = {
    'ext': f"mke2fs {ver('e2fsprogs')} (e2fsprogs, {docker})",
    'fat': f"mkfs.fat {ver('dosfstools')} and mcopy {ver('mtools')} ({docker})",
    'ntfs': f"mkntfs and ntfs-3g {ver('ntfs-3g')} ({docker})",
    'cramfs': f"mkfs.cramfs {ver('util-linux-extra')} (util-linux, {docker})",
    'disk': f"sfdisk {ver('fdisk')} (util-linux, {docker})",
    'qemu': f"qemu-img {ver('qemu-utils')} ({docker})",
    'wimlib': f"wimlib {ver('wimtools')} ({docker})",
    'nsis': f"makensis {ver('nsis')} ({docker})",
    'chm': f"chmcmd {ver('fp-utils-3.2.2')} (Free Pascal, {docker})",
    'msi': f"wixl {ver('wixl')} (msitools, {docker})",
    '7z': '7-Zip 26.00 (Windows)',
    'dmg': 'hdiutil (macOS, make-dmg.sh)',
}

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def wpath(path):
    return subprocess.run(['wslpath', '-w', path], check=True, capture_output=True, text=True).stdout.strip()

def parse(text):
    """`7z l -slt`: the level blocks' keys, and one dict per entry. Windows' 7z.exe ends lines
    with CRLF: one CR is stripped, so a CR in a name stays. A handler prints the same keys on every
    entry; a line that isn't one of them carries on the previous value."""
    lines = [l[:-1] if l.endswith('\r') else l for l in text.split('\n')]
    i = lines.index('--')
    levels, cur = [], None
    while lines[i] != '----------':
        if lines[i] == '--':
            cur = {}
            levels.append(cur)
        elif lines[i] == '----':
            cur = {}
        elif ' = ' in lines[i]:
            k, v = lines[i].split(' = ', 1)
            cur.setdefault(k, v)
        i += 1
    entries, keys, block, last = [], None, {}, None
    for line in lines[i + 1:]:
        if line == '':
            if block:
                entries.append(block)
                keys = keys or list(block)
            block, last = {}, None
            continue
        k, sep, v = line.partition(' = ')
        if sep and (keys is None or k in keys) and k not in block:
            block[k] = v
            last = k
        elif last is not None:
            block[last] += '\n' + line
    return levels, entries

def listing(path, *switches):
    p = subprocess.run([seven, 'l', '-slt', '-sccUTF-8', '-scsUTF-8', '-slmu', '-slsl', '-sns-', *switches,
                        '--', wpath(path)], capture_output=True)
    if p.returncode != 0:
        raise SystemExit(f'{path}: 7z l exited {p.returncode}: {p.stderr.decode("utf-8", "replace")}')
    return parse(p.stdout.decode('utf-8'))

def test_7z(path):
    """What `7z t` said, as make-linux.sh records it."""
    w = wpath(path)
    p = subprocess.run([seven, 't', '-sccUTF-8', w], capture_output=True)
    lines = [l.strip() for l in (p.stdout + p.stderr).decode('utf-8', 'replace').splitlines()]
    if any(re.match(r"^(Open ERROR: )?Can(no|')t open the file as (\[\w+\] )?archive$", l) for l in lines):
        return "can't open it"
    msgs = []
    for l in lines:
        l = re.sub(r'^(ERROR|Open ERROR|WARNING):\s*', '', l.replace(w, '')).strip()
        if re.search(r'(Error|There are (some )?data after|Unexpected end|Unsupported Method|CRC Failed|Is not archive)', l) \
                and not re.match(r'^(ERRORS?:|Archives with Errors|Sub items Errors|Open Errors)', l) and l not in msgs:
            msgs.append(l)
    if p.returncode == 0 and not msgs:
        return 'ok'
    if p.returncode == 0:
        return 'ok, with warnings: ' + '; '.join(msgs)
    return 'errors: ' + '; '.join(msgs)

WIRE = {'Ext': 'ext', 'FAT': 'fat', 'NTFS': 'ntfs', 'CramFS': 'cramfs', 'MBR': 'mbr', 'GPT': 'gpt',
        'QCOW': 'qcow2', 'VDI': 'vdi', 'VMDK': 'vmdk', 'VHD': 'vhd', 'VHDX': 'vhdx', 'wim': 'wim',
        'Nsis': 'nsis', 'Chm': 'chm', 'Compound': 'msi', 'Cab': 'cab', 'HFS': 'hfs', 'APFS': 'apfs'}
# Where 7-Zip's times are UTC as stored: FAT's and a cabinet's are local times, which 7-Zip turns
# into UTC at this machine's offset; CramFS and CHM have none.
UTC_TIMES = {'Ext', 'NTFS', 'wim', 'Nsis', 'HFS', 'APFS'}

def rfc3339(t):
    m = re.fullmatch(r'(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(?:\.(\d+))?Z', t)
    return f'{m.group(1)}T{m.group(2)}.{(m.group(3) or "").ljust(9, "0")}Z'

def classify(levels, raw):
    """(entry, kind, link target) for each listed entry. Kinds: a link target (`Symbolic Link`
    for ext and APFS, `Link` for WIM and NTFS) or an `l` mode (CramFS and HFS+, where the target
    is the data) is a symlink, even where 7-Zip says Folder = +; a folder is `Folder = +`, or,
    where there's no Folder key (CHM, APFS), an entry with something under it or no size (but
    NSIS lists no folders, and an unknown size for a solid installer's last file)."""
    parents = {p.rsplit('/', 1)[0] for p in (e['Path'] for e in raw) if '/' in p}
    nsis = levels[-1]['Type'] == 'Nsis'
    out = []
    for e in raw:
        mode = e.get('Mode', '')
        target = e.get('Symbolic Link') or e.get('Link') or ''
        if target or mode.startswith('l'):
            kind = 'symlink'
        elif 'Folder' in e:
            kind = 'folder' if e['Folder'] == '+' else 'other' if mode[:1] in ('c', 'b', 'p', 's') else 'file'
        else:
            kind = 'folder' if e['Path'] in parents or (e.get('Size') == '' and not nsis) else 'file'
        out.append((e, kind, target))
    return out

def extract(path):
    """`7z x -sns-` into a new folder in Windows' temp folder."""
    dest = tempfile.mkdtemp(dir=win)
    p = subprocess.run([seven, 'x', '-sns-', '-y', '-bso0', '-bsp0', '-o' + wpath(dest), '--', wpath(path)],
                       capture_output=True)
    return dest, p

def read_entry(path, name):
    """One entry's bytes through `7z x -so` (for links, whose target is their data)."""
    p = subprocess.run([seven, 'x', '-so', '-spd', '-sns-', '--', wpath(path), name], capture_output=True, check=True)
    return p.stdout

def entries_of(path):
    levels, raw = listing(path)
    dest, p = extract(path)
    inner = levels[-1]['Type']
    parents = {e['Path'].rsplit('/', 1)[0] for e in raw if '/' in e['Path']}
    entries, notes = [], []
    for e, kind, target in classify(levels, raw):
        name = e['Path']
        if kind == 'folder':
            # Two empty pseudo folders 7-Zip lists differently from one version to the next are
            # left out: NTFS's root record, `[SYSTEM]/.` (26.00; gone in 26.05), and a name with a
            # CR, which 26.00 lists as it is and 26.05 with `_` (HFS+'s private folder).
            if name.rsplit('/', 1)[-1] == '.' or any(ord(c) < 0x20 for c in name):
                continue
            if name not in parents:
                entries.append({'path': name, 'kind': 'folder'})
            continue
        if kind == 'symlink':
            if not target:
                target = read_entry(path, name).decode('utf-8')
            entries.append({'path': name, 'kind': 'symlink', 'target': target})
            continue
        if kind == 'other':
            entries.append({'path': name, 'kind': 'other'})
            continue
        with open(os.path.join(dest, *name.split('/')), 'rb') as f:
            data = f.read()
        if e.get('Size') != str(len(data)):
            notes.append(f"`{name}` is listed with size {e.get('Size') or '(none)'} and extracts to {len(data)} bytes")
        x = {'path': name, 'kind': 'file', 'size': len(data), 'sha256': sha256(data)}
        if inner in UTC_TIMES and e.get('Modified'):
            x['mtime'] = rfc3339(e['Modified'])
        entries.append(x)
    if p.returncode != 0:
        # Windows' 7-Zip can't make every link (symlinks need Developer Mode); the files are read
        # above, so a file it couldn't write has already failed.
        err = ' '.join(p.stderr.decode('utf-8', 'replace').split())
        print(f'{os.path.basename(path)}: 7z x exited {p.returncode}: {err}', file=sys.stderr)
    return levels, entries, notes

# The tree, for the cross-checks.
tree = {}
with tarfile.open(os.path.join(made, 'tree.tar')) as t:
    for m in t.getmembers():
        if '/' not in m.name:
            continue
        rel = m.name.split('/', 1)[1]
        if m.isfile() or m.islnk():
            tree[rel] = ('file', sha256(t.extractfile(m).read()))
        elif m.issym():
            tree[rel] = ('symlink', m.linkname)

def crosscheck(name, entries, prefix='', only=None, renames={}, as_files=(), skip=()):
    """Every file and link of the tree (or of `only`, a folder of it) is in the record, with the
    same bytes or target, under `prefix`."""
    got = {e['path']: e for e in entries}
    for rel, (kind, value) in tree.items():
        if rel in skip or (only and not rel.startswith(only + '/')):
            continue
        want = prefix + renames.get(rel, rel[len(only) + 1:] if only else rel)
        e = got.get(want)
        if rel in as_files:
            kind, value = 'file', tree[value][1]
        if e is None or e['kind'] != kind or e.get('sha256' if kind == 'file' else 'target') != value:
            raise SystemExit(f'{name}: {want} is {e}, not {kind} {value}')

def image(name):
    return os.path.join(out, name)

def file_sha(path):
    with open(path, 'rb') as f:
        return sha256(f.read())

COMMON = ('Entries are what 7-Zip 26.00 lists (`7z l -slt -sccUTF-8 -scsUTF-8 -slmu -slsl -sns-`), its pseudo '
          'entries included, with the bytes `7z x -sns-` extracts; an empty folder is an entry of kind `folder`, '
          'and a hard link is listed as a second file.')
MTIME = '2026-01-01T00:00:00.000000000Z'
TIMES = (' utc_mtimes is false: mtime.txt is 2024-05-06T07:08:09.123456789Z; each file\'s `mtime` is the time '
         '7-Zip lists, in UTC.')
UTC = ' Every file\'s time is 2026-01-01T00:00:00Z; each file\'s `mtime` is the time 7-Zip lists, in UTC.'
NO_TIMES = {
    'fat': ' FAT holds local times, which 7-Zip turns into UTC at the offset of the machine it runs on, so '
            'files have no `mtime`.',
    'cab': ' A cabinet holds local times, which 7-Zip turns into UTC at the offset of the machine it runs on, '
           'so files have no `mtime`.',
    'cramfs': ' CramFS holds no times.',
    'chm': ' CHM holds no times.',
    'parts': ' The entries are partitions, which have no times.',
}
FAT = (' mcopy copied link-to-readme as a file and skipped sub/link-to-nested (FAT has no links); mtools '
       '4.0.43 keeps only the low 16 bits of a character outside the BMP, so bee-🐝.txt (U+1F41D) is stored as '
       'bee-<U+F41D>.txt.')
NTFS = (' [SYSTEM]/… are 7-Zip\'s views of the metadata files; 7-Zip 26.00 also lists [SYSTEM]/., the root '
        'folder\'s own record, which 26.05 doesn\'t and the record leaves out. The symlinks are NTFS symlink reparse points, listed with `Link` and attribute L; '
        'readme.txt (and its hard link) has an alternate data stream, `hidden`, which -sns- leaves out of '
        'the listing and the extraction.')
PARTS = (' 7-Zip opens the disk\'s levels itself and stops at a disk with several partitions, which it lists '
         'as files named index.name.type: 0.data.fat is fat12.img and 1.linux.img an ext4 without a journal '
         '(384 KiB), byte for byte.')

records = []
def record(name, producer, command, note, check=None, kind=None):
    path = image(name)
    levels, entries, notes = entries_of(path)
    chain = WIRE[levels[0]['Type']]
    inner = levels[-1]['Type']
    if check:
        check(name, entries)
    r = {'file': '7zip/' + name, 'producer': producer, 'command': command, 'chain': chain, 'backend': '7-zip',
         'levels': [WIRE[l['Type']] for l in levels], 'password': None, 'utc_mtimes': False, 'hardlinks': 0,
         'symlinks': sum(1 for e in entries if e['kind'] == 'symlink')}
    others = sum(1 for e in entries if e['kind'] == 'other')
    if others:
        r['others'] = others
    r['7z_test'] = test_7z(path)
    r['entries'] = entries
    files = [e for e in entries if e['kind'] == 'file']
    if inner in UTC_TIMES and all(e.get('mtime') == MTIME for e in files):
        r['utc_mtimes'] = True
        times = UTC
    else:
        times = TIMES if inner in UTC_TIMES else NO_TIMES[kind or WIRE[inner]]
    r['note'] = ' '.join([COMMON + times + note] + [n + '.' for n in notes]).strip()
    records.append(r)
    return r

tree_check = lambda name, entries: crosscheck(name, entries)
fat_check = lambda name, entries: crosscheck(name, entries, renames={'bee-🐝.txt': 'bee-\uf41d.txt'},
                                             as_files={'link-to-readme': 'readme.txt'}, skip={'sub/link-to-nested'})
def parts_check(name, entries):
    want = {'0.data.fat': file_sha(image('fat12.img')), '1.linux.img': file_sha(os.path.join(made, 'parts', 'gpt-ext4.img'))}
    got = {e['path']: e.get('sha256') for e in entries}
    if got != want:
        raise SystemExit(f'{name}: partitions {got}, not {want}')

E = 'mke2fs -b 1024 -U <fixed> -E hash_seed=<fixed>,root_owner=0:0 -d tree'
record('ext4.img', PRODUCER['ext'], f'{E} -t ext4 -I 256 ext4.img 2M; debugfs sets the change times and mtime.txt\'s nanoseconds',
       ' [SYS]/Journal is the journal\'s inode; lost+found is empty. sub/link-to-nested, a symlink to a folder, '
       'is listed with Folder = +.', tree_check)
record('ext2.img', PRODUCER['ext'], f'{E} -t ext2 -I 128 ext2.img 256K; debugfs sets the change times',
       ' 128-byte inodes hold whole seconds: mtime.txt is listed at 07:08:09.', tree_check)
record('fat12.img', PRODUCER['fat'], 'mkfs.fat --invariant -F 12 -i 6D7A6970 -C fat12.img 256; mcopy -s -p -m tree/* ::/',
       FAT, fat_check)
record('fat32.img', PRODUCER['fat'], 'mkfs.fat --invariant -F 32 -i 6D7A6970 -C fat32.img 1024; mcopy -s -p -m tree/* ::/',
       FAT + ' FAT32 in 1 MiB has fewer clusters than the 65 525 the specification asks; its BIOS parameter '
       'block says FAT32, which 7-Zip goes by.', fat_check)
record('ntfs.img', PRODUCER['ntfs'], 'mkntfs -Q ntfs.img (1280 KiB); ntfs-3g -o streams_interface=windows; cp -a tree; '
       'symlinks through system.ntfs_reparse_data; echo > readme.txt:hidden (under a frozen libfaketime clock)',
       NTFS, tree_check)
def cramfs_check(name, entries):
    crosscheck(name, entries)
r = record('cramfs.img', PRODUCER['cramfs'], 'mkfs.cramfs -n BeeZipCramfs tree cramfs.img',
           ' The symlinks have mode l and no link key: their targets are their data. Windows\' 7-Zip decodes '
           'CramFS names with the OEM code page (CP437 here: bee-🐝.txt is listed as bee-≡ƒÉ¥.txt, and -mcp '
           'is refused), so the paths here are the names as stored, in UTF-8: BeeZip has to encode what '
           '7-Zip lists back with the OEM code page.', kind='cramfs')
# The CramFS names: back from the OEM code page (437 on this machine) to their UTF-8 bytes.
oem = subprocess.run(['reg.exe', 'query', r'HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage', '/v', 'OEMCP'],
                     capture_output=True, check=True, cwd='/mnt/c').stdout.decode('ascii', 'replace')
cp = 'cp' + re.search(r'OEMCP\s+REG_SZ\s+(\d+)', oem).group(1)
for e in r['entries']:
    e['path'] = e['path'].encode(cp).decode('utf-8')
cramfs_check('cramfs.img', r['entries'])
record('mbr-fat.img', PRODUCER['disk'], 'sfdisk (dos, label-id 0x6d7a6970, start=64, type=1); fat12.img at sector 64',
       FAT, fat_check)
record('gpt-fat-ext4.img', PRODUCER['disk'], 'sfdisk (gpt, fixed label-id and uuids, start=64: "data" FAT12, "linux" ext4); '
       'fat12.img and an ext4 without a journal in them', PARTS, parts_check, kind='parts')
record('gpt-ntfs.img', PRODUCER['disk'], 'sfdisk (gpt, fixed label-id and uuid, start=64: "ntfs"); ntfs.img in it',
       ' 7-Zip opens GPT > NTFS: a disk with one partition shows that partition\'s files.' + NTFS, tree_check)
Q = 'qemu-img convert -f raw'
record('gpt-fat-ext4.qcow2', PRODUCER['qemu'], f'{Q} -O qcow2 gpt-fat-ext4.img gpt-fat-ext4.qcow2', PARTS, parts_check, kind='parts')
record('gpt-fat-ext4.vdi', PRODUCER['qemu'], f'{Q} -O vdi gpt-fat-ext4.img gpt-fat-ext4.vdi (UUIDs fixed afterwards)', PARTS,
       parts_check, kind='parts')
record('gpt-fat-ext4.vmdk', PRODUCER['qemu'], f'{Q} -O vmdk -o subformat=monolithicSparse gpt-fat-ext4.img gpt-fat-ext4.vmdk '
       '(CID fixed afterwards)', PARTS, parts_check, kind='parts')
record('mbr-fat.vhd', PRODUCER['qemu'], f'{Q} -O vpc -o subformat=dynamic,force_size=on mbr-fat.img mbr-fat.vhd (unique id '
       'fixed afterwards)', ' 7-Zip opens VHD > MBR > FAT, and lists the VHD\'s time stamp (2026-01-01T00:00:00Z) at this '
       'machine\'s offset.' + FAT, fat_check)
record('mbr-fat-fixed.vhd', PRODUCER['qemu'], f'{Q} -O vpc -o subformat=fixed,force_size=on mbr-fat.img mbr-fat-fixed.vhd '
       '(unique id fixed afterwards)', ' A fixed VHD is the raw disk and a footer.' + FAT, fat_check)
record('gpt-ntfs.vhdx', PRODUCER['qemu'], f'{Q} -O vhdx -o block_size=1M,log_size=1M gpt-ntfs.img gpt-ntfs.vhdx (GUIDs and '
       'sequence numbers fixed, the empty log zeroed and the payload moved down from 8 MiB afterwards)',
       ' 7-Zip opens VHDX > GPT > NTFS. The disk is a whole number of KiB: 7-Zip 26.00 can\'t open a VHDX of '
       'a disk an odd number of sectors long.' + NTFS, tree_check)
def wim_check(name, entries):
    crosscheck(name, entries, prefix='1/')
    crosscheck(name, entries, prefix='2/', only='sub')
record('wimlib.wim', PRODUCER['wimlib'], 'wimcapture tree wimlib.wim BeeZip --compress=lzx; wimappend tree/sub wimlib.wim Sub '
       '(GUID fixed afterwards)', ' Two images: 7-Zip puts each under its index (1/, 2/) and lists the WIM\'s XML as '
       '[1].xml. The symlinks are reparse points, listed with `Link`, attribute L and the reparse data\'s size; '
       'the one to a folder with Folder = +.', wim_check)
record('wimlib-solid.esd', PRODUCER['wimlib'], 'wimcapture tree wimlib-solid.esd BeeZip --solid (GUID fixed afterwards)',
       ' Solid LZMS. The symlinks are reparse points, listed with `Link`, attribute L and the reparse data\'s '
       'size; the one to a folder with Folder = +.', tree_check)
record('tree.wim', PRODUCER['7z'], '7z a -twim tree.wim * (in the tree, written to NTFS without its symlinks, the hard link '
       'as a copy)', ' Made on Windows by 7-Zip itself; its GUID and XML times are fixed afterwards.',
       lambda name, entries: crosscheck(name, entries, skip={'link-to-readme', 'sub/link-to-nested'}))
nsis_files = [r for r, (k, _) in tree.items() if k == 'file']
for comp, method in [('lzma', 'SetCompressor /SOLID lzma'), ('zlib', 'SetCompressor zlib'), ('bzip2', 'SetCompressor bzip2')]:
    record(f'nsis-{comp}.exe', PRODUCER['nsis'], f'makensis -INPUTCHARSET UTF8 {comp}.nsi ({method}; File for each of the '
           'tree\'s files, under $INSTDIR)', ' 7-Zip lists the files under $INSTDIR from the root, with the sizes the '
           'script records: `size` is what 7z x extracts. makensis stores times to 2 s.',
           lambda name, entries: crosscheck(name, entries, skip={'link-to-readme', 'sub/link-to-nested'}))
record('chmcmd.chm', PRODUCER['chm'], 'chmcmd fixture.hhp (index.htm, pages/a.htm, pages/café.htm; time stamps zeroed afterwards)',
       ' 7-Zip lists the folder pages as a 0-byte entry with no Folder key, and CHM\'s own files (#SYSTEM, $OBJINST, '
       '#IDXHDR, #STRINGS, #ITBITS, _#_README_#_).')
def msi_check(name, entries):
    got = {e['path']: e.get('sha256') for e in entries}
    want = {'readme': tree['readme.txt'][1], 'empty': tree['empty.txt'][1], 'random': tree['random.bin'][1], 'cjk': tree['名前.txt'][1]}
    if got != want:
        raise SystemExit(f'{name}: {got}')
record('wixl.msi', PRODUCER['msi'], 'wixl -o wixl.msi fixture.wxs (readme.txt, empty.txt, random.bin, 名前.txt; package code '
       'fixed afterwards)', ' 7-Zip opens the Compound file\'s embedded cabinet (Compound > Cab) and lists its files '
       'under their File table keys (readme, empty, random, cjk), not their names.', msi_check)

# HFS+ and APFS: the DMG fixtures' records hold the same files (HFS+'s names composed).
dmg = {r['file']: r for r in json.load(open(os.path.join(here, 'manifest.json'), encoding='utf-8'))['fixtures']
       if r['file'].startswith('dmg/')}
def dmg_check(src, prefix):
    def check(name, entries):
        got = {unicodedata.normalize('NFC', e['path']): e for e in entries}
        for want in dmg[src]['entries']:
            e = got.get(prefix + want['path'])
            if e is None or e['kind'] != want['kind'] or e.get('sha256') != want.get('sha256') or e.get('target') != want.get('target'):
                raise SystemExit(f'{name}: {prefix + want["path"]} is {e}, not {want}')
    return check
record('dmg-hfs.hfs', PRODUCER['dmg'], '7z e -tdmg dmg/hfs-udro.dmg 4.hfs (the HFS+ volume, as it is in the DMG)',
       ' 7-Zip puts the volume\'s name (BeeZip HFS) above its files, lists names decomposed (NFD) as HFS+ stores '
       'them, and lists the private folders: `[HFS+ Private Data]` (stored with four NULs in front), and '
       '`.HFS+ Private Directory Data` with a CR at its end, which 7-Zip 26.00 lists as it is and 26.05 with `_`, '
       'so the record leaves it out. The symlink has mode l and no link key: its '
       'target is its data.', dmg_check('dmg/hfs-udro.dmg', 'BeeZip HFS/'))
record('dmg-apfs.apfs', PRODUCER['dmg'], '7z e -tdmg dmg/apfs-udro.dmg 4.apfs (the APFS container, as it is in the DMG)',
       ' 7-Zip lists no Folder key: a folder has no size. The symlink is listed with size 11, its target and a NUL.',
       dmg_check('dmg/apfs-udro.dmg', ''))

# manifest.json: the 7zip/ records go where the old ones were.
manifest_path = os.path.join(here, 'manifest.json')
with open(manifest_path, encoding='utf-8') as f:
    manifest = json.load(f)
old = manifest['fixtures']
mine = lambda r: r['file'].startswith('7zip/')
at = next((i for i, r in enumerate(old) if mine(r)), len(old))
manifest['fixtures'] = old[:at] + records + [r for r in old[at:] if not mine(r)]
with open(manifest_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(json.dumps(manifest, indent=2, ensure_ascii=False))

# The README: the files, and what 7-Zip lists for the malicious ones.
def size(n):
    return f'{n / 1048576:.1f} MiB' if n >= 1048576 else f'{n / 1024:.0f} KiB'
rows = '\n'.join(f"| `{r['file'][5:]}` | {size(os.path.getsize(image(r['file'][5:])))} | {' > '.join(r['levels'])} | "
                 f"{r['producer']} |" for r in records)
def md(s):
    # In a code span in a table: `|` escaped, CR and LF as \r and \n, and the U+EF80–U+EFFF that
    # 7-Zip lists for bytes that aren't UTF-8 as \xNN.
    s = s.replace('|', '\\|').replace('\r', '\\r').replace('\n', '\\n')
    return ''.join(f'\\x{ord(c) - 0xEF00:02x}' if 0xEF80 <= ord(c) <= 0xEFFF else c for c in s)
def listed(name):
    levels, raw = listing(os.path.join(mal, name))
    lines = ['| Path | Kind | Size | Link |', '|---|---|---|---|']
    for e, kind, target in classify(levels, raw):
        mode = e.get('Mode', '')
        k = {'c': 'character device', 'p': 'FIFO'}.get(mode[:1], kind)
        lines.append(f"| `{md(e['Path'])}` | {k} | {e.get('Size') or ''} | {'`' + md(target) + '`' if target else ''} |")
    return '\n'.join(lines)
readme = f'''# Fixtures for the 7-Zip backend

Made by `tests/fixtures/make-7z.sh` (docs/M6.md §10), which also writes this file and the records
in `manifest.json`. Every image holds the same seeded tree, as far as its file system can: text, an
empty file, 64 KiB of pseudo-random bytes, nested folders, names in CJK, an emoji, accents and a
space, a folder with a non-ASCII name, a symlink, a symlink to a folder and a hard link, every time
2026-01-01T00:00:00Z but `mtime.txt`'s (2024-05-06T07:08:09.123456789Z). A record's `levels` are the
types 7-Zip opens, outermost first; its `note` says what 7-Zip does with the format that a reader of
its listing should know.

Each image is as small as its tool makes it, mostly zeros: ext4's journal is at least 1 MiB, NTFS
at least 1 MiB, a VHDX's header, log, metadata and block table take 1 MiB each and its blocks
1 MiB (qemu-img's payload, which starts at 8 MiB, is moved down), a dynamic VHD's block is 2 MiB,
and the APFS container is the one hdiutil made (10.5 MiB, 104 KiB compressed).

| File | Size | Levels | Made by |
|---|---|---|---|
{rows}

## Malicious images

In `tests/fixtures/malicious/`, not in `manifest.json`. What 7-Zip 26.00 on Windows lists for each
(`7z l -slt -sccUTF-8 -slmu -slsl -sns-`; `\\r` and `\\n` stand for the characters, `\\xNN` for
the U+EF80–U+EFFF 7-Zip lists for a byte that isn't UTF-8), and what BeeZip must do. Nothing may
be written outside the destination, and every rule is FsSink's, applied to the names 7-Zip lists,
never 7-Zip's own renaming.

### `ext4-hostile.img`

An ext4 image (no journal) whose names and links can't be trusted. ext allows any byte in a name
but `/` and NUL; Windows' 7-Zip turns `\\` (and `\\n`) into `_` when it lists, 7-Zip on Linux may not.

{listed('ext4-hostile.img')}

BeeZip must:
- extract `safe.txt` and `dir/inside.txt` as they are, and rename `...` (Windows drops trailing
  dots and spaces, so it would name the folder itself);
- never let `.. ` (which Windows would trim to `..`) or `.._.._escape.txt` (or `..\\..\\escape.txt`)
  climb out: `.. /escape.txt` is refused as traversal or renamed so it stays inside;
- land `C:/drive.txt` inside (the drive made relative or renamed, as `absolute.zip`'s);
- rename `ads:stream.txt` (no alternate stream), `CON` and `aux.txt` (`_CON`, `_aux.txt`), the
  name with a CR and the forged name with `_` for what Windows can't hold;
- turn `bad\\xff\\xfe.txt` back into its bytes and write it as BeeZip writes any name that isn't
  UTF-8;
- treat `trail.` and `trail ` as two names that become one (`trail_`) only once made safe: the
  overwrite policy decides, never "the same path twice";
- skip the character device `null` and the FIFO `fifo` (kind `other`);
- with links off, skip every link; with links on, refuse `link-rel`, `link-abs`, `link-drive`,
  `link-unc` and `link-up` as leading out, and make `link-dir` (listed with Folder = +, a link all
  the same).

### `ext4-sparse-100g.img`

A 256 KiB ext4 image holding one sparse file that claims 100 GB (107 374 182 400 bytes: `start` at
0, `end` at the end, holes between).

{listed('ext4-sparse-100g.img')}

BeeZip must refuse it before 7-Zip starts (LimitExceeded: the listed 100 GB is more than the
default `max_ratio`, 10 000, times the image's 256 KiB), and leave nothing behind, `safe.txt`
included; `archive.test` must stop the same way rather than read 100 GB of holes.

### `wim-links-out.wim`

A WIM from wimlib (`wimcapture --norpfix`) whose symlinks, stored as reparse points, lead out.

{listed('wim-links-out.wim')}

BeeZip must extract `safe.txt` and `dir/inside.txt`; with links off, skip the links; with links
on, refuse `link-rel`, `link-abs` and `link-up` as leading out (the targets keep their `\\`), and
make `link-dir`.
'''
with open(os.path.join(out, 'README.md'), 'w', encoding='utf-8', newline='\n') as f:
    f.write(readme)

for r in records:
    print(f"{r['file']}: {len(r['entries'])} entries, {r['symlinks']} symlinks; 7z t {r['7z_test']}")
PY
du -cb "$out"/* "$here/malicious"/ext4-*.img "$here/malicious"/wim-links-out.wim | tail -n 1
