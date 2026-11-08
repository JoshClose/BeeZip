# ZOO fixtures

Made by `tests/fixtures/make-retro.sh` (docs/M6.md §10) in Docker (make-retro.Dockerfile), which
also writes this file and the records in `manifest.json`; a rerun writes the same bytes.

The tree: `readme.txt`, `empty.txt`, `text.txt` (80 lines of text), `random.bin` (1 KiB of Python's Random(42)), `mtime.txt` and `sub/nested/deep.txt`; ZOO stores no folders, so each file is
named on the command line.

zoo 2.10 leaves the bytes after the NUL of an entry's 13-byte short name uninitialised (stack
garbage, different every run); make-retro.sh zeroes them and makes the entry's CRC-16 again.

| File | Size | Made by | Command |
|---|---|---|---|
| `stored.zoo` | 5.7 KiB | zoo 2.10 (Debian 9's zoo 2.10-28, in Docker) | `zoo af stored.zoo readme.txt empty.txt text.txt random.bin mtime.txt sub/nested/deep.txt` |
| `lzw.zoo` | 2.4 KiB | zoo 2.10 (Debian 9's zoo 2.10-28, in Docker) | `zoo a lzw.zoo readme.txt empty.txt text.txt random.bin mtime.txt sub/nested/deep.txt` |
| `lh5.zoo` | 1.8 KiB | zoo 2.10 (Debian 9's zoo 2.10-28, in Docker) | `zoo ah lh5.zoo readme.txt empty.txt text.txt random.bin mtime.txt sub/nested/deep.txt` |
