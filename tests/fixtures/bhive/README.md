# `.bhive` fixtures

Written by `cargo xtask gen-fixtures` (`xtask/src/fixtures/bhive.rs`); `--check` fails when a
file here differs from what it would write. `manifest.json` says what each archive must list
and hold. `crates/beezip-core/tests/bhive.rs` checks BeeZip against it, and
`docs/bhive_reader.py`, the reader written from the specification alone.

| File | What |
|---|---|
| `none.bhive`, `fast.bhive`, `balanced.bhive`, `high.bhive`, `max.bhive` | one tree at each level, in the level's own cells: empty and tiny files, text and noise, names beyond ASCII, a copy and a shifted copy, folders, a link, every kind of metadata |
| `cells.bhive`, `probe.bhive`, `max-cells.bhive` | Balanced, High and Max in small cells: files across cells, extents into earlier cells, stored cells beside LZMA2 ones |
| `empty.bhive`, `folders.bhive` | no entries; entries without bytes, in a record with an empty cell |
| `times.bhive` | times before 1970 and 1601, in 9999, to the nanosecond, and none (built by hand) |
| `three-cells.bhive`, `cut.bhive`, `added.bhive` | three stored cells built by hand; the same cut short in its third cell, which reads with `recover`; the same added to in place, with a second index block |
| `spec-empty.bhive`, `spec-small.bhive` | the examples of `docs/bhive.md` §11, byte for byte |

**These are version 1 files, and stay.** Version 1 of the format is frozen when BeeZip 0.8.0 is
released (docs/M13.md decision 16). From then on, if a dependency's update changes the bytes
BeeZip writes (a new zstd compresses differently), `gen-fixtures --check` will say these are
out of date: keep them as they are, since every later BeeZip must read what 0.8.0 wrote, and
add the new writer's files beside them under new names.

The malicious `.bhive` files are in `../malicious/` with the others.
