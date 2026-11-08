# ARJ fixtures

Made by `tests/fixtures/make-retro.sh` (docs/M6.md §10) in Docker (make-retro.Dockerfile), which
also writes this file and the records in `manifest.json`; a rerun writes the same bytes.

The tree: `readme.txt`, `empty.txt`, `text.txt` (80 lines of text), `random.bin` (1 KiB of Python's Random(42)), `mtime.txt` and `sub/nested/deep.txt`, and the empty folder `emptydir`; every time 2026-01-01T00:00:00Z but mtime.txt's, 2024-05-06T07:08:09Z. `volumes.arj` holds `readme.txt` and 21 000 bytes that don't compress,
`names-cp437.arj` two files with CP437 names (`café.txt`, `Ünïcödé/ñandú.txt`).

arj on Linux writes Unix-host archives: their times are Unix times, which 7-Zip and unarc-rs read
as MS-DOS times (decades off); the records hold the true ones. `-j$` leaves out the accessed and
created times, which would make every run different, and arj ran under a frozen clock for the
archive's own times. `dos.arj` (-2d) is an MS-DOS-host archive with MS-DOS times.

| File | Size | Made by | Command |
|---|---|---|---|
| `m0.arj` | 5.7 KiB | ARJ 3.10.22 (Debian 12's arj 3.10.22-26, in Docker) | `arj a -r -a1 -j$ -y -m0 m0.arj *` |
| `m1.arj` | 1.8 KiB | ARJ 3.10.22 (Debian 12's arj 3.10.22-26, in Docker) | `arj a -r -a1 -j$ -y -m1 m1.arj *` |
| `m2.arj` | 1.8 KiB | ARJ 3.10.22 (Debian 12's arj 3.10.22-26, in Docker) | `arj a -r -a1 -j$ -y -m2 m2.arj *` |
| `m3.arj` | 1.8 KiB | ARJ 3.10.22 (Debian 12's arj 3.10.22-26, in Docker) | `arj a -r -a1 -j$ -y -m3 m3.arj *` |
| `m4.arj` | 1.9 KiB | ARJ 3.10.22 (Debian 12's arj 3.10.22-26, in Docker) | `arj a -r -a1 -j$ -y -m4 m4.arj *` |
| `jm.arj` | 1.8 KiB | ARJ 3.10.22 (Debian 12's arj 3.10.22-26, in Docker) | `arj a -r -a1 -j$ -y -jm jm.arj *` |
| `garbled.arj` | 1.9 KiB | ARJ 3.10.22 (Debian 12's arj 3.10.22-26, in Docker) | `arj a -r -a1 -j$ -y -m1 -gbeezip garbled.arj *` |
| `dos.arj` | 1.8 KiB | ARJ 3.10.22 (Debian 12's arj 3.10.22-26, in Docker) | `arj a -r -a1 -j$ -y -m1 -2d dos.arj *` |
| `volumes.arj`, `volumes.a01`, `volumes.a02` | 20.9 KiB | ARJ 3.10.22 (Debian 12's arj 3.10.22-26, in Docker) | `arj a -j$ -y -m1 -v10000 volumes.arj readme.txt random.bin` |
| `names-cp437.arj` | 198 B | ARJ 3.10.22 (Debian 12's arj 3.10.22-26, in Docker) | `arj a -r -j$ -y -m1 names-cp437.arj *` |
