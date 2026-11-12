# The tools make-7z.sh runs in a container (docs/M6.md §10): file systems (e2fsprogs, dosfstools
# and mtools, ntfs-3g through FUSE, mkfs.cramfs), partition tables (sfdisk), qemu-img's virtual
# disks, wimlib, makensis, wixl, chmcmd (Free Pascal's CHM compiler) and Halibut (PuTTY's
# documentation tool, which writes CHMs with its own LZX encoder: make-chm.sh), with libfaketime for
# the tools that take the time from the clock. make-7z.sh builds it as beezip-fixtures-7z.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        e2fsprogs dosfstools mtools ntfs-3g fuse3 util-linux-extra fdisk qemu-utils \
        wimtools nsis wixl msitools fp-utils-3.2.2 halibut faketime python3 \
    && rm -rf /var/lib/apt/lists/*
