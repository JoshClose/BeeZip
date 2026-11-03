//! CLI snapshot tests (docs/M1.md §6): `tests/cmd/*.toml` with their `.stdout`/`.stderr`.
//! Regenerate the snapshots with `TRYCMD=overwrite cargo test -p beezip-cli --test trycmd`.

#[test]
fn cli_cases() {
    trycmd::TestCases::new()
        .default_bin_name("beezip")
        // The developer's own config must not change what the CLI prints.
        .env("BEEZIP_CONFIG", "no-such-beezip-config.toml")
        .case("tests/cmd/*.toml");
}
