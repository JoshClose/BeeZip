# hadris-iso 3.0.0-rc.3, patched for BeeZip

This is hadris-iso 3.0.0-rc.3 as published on crates.io (MIT, see LICENSE-MIT; the source is
https://github.com/hxyulin/hadris), with two fixes. The workspace uses it through
`[patch.crates-io]` (docs/M5.md §5.9). Cargo normalised `Cargo.toml` when the crate was
published; its examples, tests and benchmark aren't vendored, so their targets are gone. Each fix
is in `patches/`, made against the published crate, and the copy goes when upstream has them.

- **`patches/dedup.diff`** (`src/plan/directory.rs`): the name de-duplication tried every suffix
  from 1 for every colliding name, so 20 000 files whose long names share a prefix took 80 s to
  plan, at any ISO level. It now remembers the next suffix to try for each name: 0.12 s.
- **`patches/symlink.diff`** (`src/rock_ridge.rs`): Rock Ridge `SL` components were joined
  without the `/` after an empty component, and a root in the middle of a target was dropped, so
  `.///file` read as `./file` and `/tmp//..` as `/tmp/..`. They're joined now as libarchive and
  Linux join them (libarchive's rockridge test images), with a unit test.

hadris-iso's own unit tests pass with both (`cargo test --lib` in a copy with a `[workspace]`
table of its own).
