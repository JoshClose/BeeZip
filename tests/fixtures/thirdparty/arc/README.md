# ARC fixtures

Made by `tests/fixtures/make-retro.sh` (docs/M6.md §10) in Docker (make-retro.Dockerfile), which
also writes this file and the records in `manifest.json`; a rerun writes the same bytes.

ARC stores names only (DOS names, no folders), and arc 5.21q picks each file's method
itself, so the files are chosen for what arc does with them: `TEXT.TXT` (80 lines of text)
crunches or squashes, `RUNS.DAT` (runs of bytes) crunches or packs, `SQZ.DAT` and `CUT.DAT` (2 001
and 2 000 bytes from an 8-letter alphabet) are squeezed, `RANDOM.BIN`, `README.TXT` and
`EMPTY.TXT` are stored. arc is Debian's i386 build: on amd64 it made only stored entries.

arc 5.21q never writes a squeezed stream's last partial byte: `SQZ.DAT`'s end code happens to end
on a byte, `CUT.DAT`'s (`squeeze-cut.arc`) is cut short, though all its data is there, and arc
reads it. unar 1.10.1 fails `CUT.DAT` and crashes part-way through `crunched.arc` and
`squashed.arc`; the records' notes say what it extracts.

| File | Size | Made by | Command |
|---|---|---|---|
| `crunched.arc` | 3.0 KiB | ARC 5.21q (Debian 12's arc:i386 5.21q-12, in Docker) | `arc a crunched.arc README.TXT EMPTY.TXT TEXT.TXT RUNS.DAT SQZ.DAT RANDOM.BIN` |
| `squashed.arc` | 3.0 KiB | ARC 5.21q (Debian 12's arc:i386 5.21q-12, in Docker) | `arc aq squashed.arc README.TXT EMPTY.TXT TEXT.TXT RUNS.DAT SQZ.DAT RANDOM.BIN` |
| `garbled.arc` | 948 B | ARC 5.21q (Debian 12's arc:i386 5.21q-12, in Docker) | `arc agBEEZIP garbled.arc README.TXT TEXT.TXT` |
| `squeeze-cut.arc` | 872 B | ARC 5.21q (Debian 12's arc:i386 5.21q-12, in Docker) | `arc a squeeze-cut.arc CUT.DAT` |
