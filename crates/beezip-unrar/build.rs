//! unrar_sys 0.5.8's build script links powrprof and shell32 but not advapi32, which UnRAR's
//! registry, token and CryptoAPI calls need (RegOpenKeyExW, OpenProcessToken, CryptGenRandom,
//! SetFileSecurityW…). Rust's std no longer links it, so MSVC builds fail with 13 unresolved
//! symbols without this (docs/M3.md §3.4, §11).

fn main() {
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        println!("cargo:rustc-link-lib=advapi32");
    }
}
