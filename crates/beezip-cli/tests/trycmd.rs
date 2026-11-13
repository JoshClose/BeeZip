//! CLI snapshot tests (docs/M1.md §6): `tests/cmd/*.toml` with their `.stdout`/`.stderr`.
//! Regenerate the snapshots with `TRYCMD=overwrite cargo test -p beezip-cli --test trycmd`.

#[test]
fn cli_cases() {
    trycmd::TestCases::new()
        .default_bin_name("beezip")
        // The developer's own config must not change what the CLI prints: the cases run with the
        // defaults.
        .env(
            "BEEZIP_CONFIG",
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/cli-config.toml"),
        )
        // Nor its Explorer menu: `settings set shell.…` updates an installed one (debug builds).
        .env("BEEZIP_SHELL_BASE", r"Software\BeeZip-trycmd")
        .case("tests/cmd/*.toml")
        .skip("tests/cmd/settings-*.toml");
}

/// The `settings` cases each name their own `config.toml` in `env.add`: trycmd lets the
/// suite's environment win over a case's, so they can't share the cases above.
#[test]
fn settings_cases() {
    trycmd::TestCases::new()
        .default_bin_name("beezip")
        .env("BEEZIP_SHELL_BASE", r"Software\BeeZip-trycmd")
        .case("tests/cmd/settings-*.toml");
}
