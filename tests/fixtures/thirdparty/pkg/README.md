# macOS package fixtures

Made by `tests/fixtures/make-xar.sh` (docs/M6.md §10) in Docker (make-xar.Dockerfile), without a
Mac, which also writes this file and the records in `manifest.json`; a rerun writes the same bytes.
`macos/` holds packages made by pkgbuild and productbuild on GitHub's macOS runner
(`.github/workflows/make-pkg.yml`, merged by `merge-pkg.py`, which owns those records).

Each package's Payload holds `usr/local/bin/hello` (0755), the symlink `usr/local/bin/hello-readme`
(to `../share/hello/README`), `usr/local/share/hello/README`, `usr/local/share/hello/Ünïcödé.txt`
and the empty folder `usr/local/share/hello/empty`; its Scripts `preinstall` and `postinstall`.
Payload and Scripts are cpio in odc format (`find . | sort | cpio -o -H odc --owner 0:80`), gzip'd
as pkgbuild writes them, or, in `pbzx.pkg`, the Payload pbzx: Apple's chunked xz (the magic, the
16 MiB chunk size, then per chunk its size, packed size and bytes), from a writer in the script.
The Bom is mkbom's (bomutils), PackageInfo and Distribution are written by hand; Bom, PackageInfo
and Distribution are stored gzip'd in the XAR, Payload and Scripts as they are, as Apple's tools
store them. The packages aren't signed.

BeeZip lists a package as `pkgutil --expand-full` lays it out: Payload and Scripts become folders
of their cpio's contents, everything else stays a file; a product archive's components are folders
expanded the same way. The records hold that layout, made in the container with xar -x and cpio -i.

| File | Size | Made by | Command |
|---|---|---|---|
| `component.pkg` | 2.0 KiB | xar 1.6.1, mkbom (bomutils c247002) and GNU cpio 2.15 (in Docker) | `xar -c -f component.pkg --compression=gzip --no-compress='^(.*/)?(Payload|Scripts)$' Bom PackageInfo Payload Scripts` |
| `product.pkg` | 2.7 KiB | xar 1.6.1, mkbom (bomutils c247002) and GNU cpio 2.15 (in Docker) | `xar -c -f product.pkg --compression=gzip --no-compress='^(.*/)?(Payload|Scripts)$' Distribution Resources hello.pkg` |
| `pbzx.pkg` | 2.1 KiB | xar 1.6.1, mkbom (bomutils c247002) and GNU cpio 2.15 (in Docker) | `xar -c -f pbzx.pkg --compression=gzip --no-compress='^(.*/)?(Payload|Scripts)$' Bom PackageInfo Payload Scripts` |
