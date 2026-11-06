//! Passes `beezip_shell.def` to link.exe, which exports COM's two entry points as PRIVATE
//! (docs/M4.md §4.4).

fn main() {
    println!("cargo:rerun-if-changed=beezip_shell.def");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|e| e == "msvc");
    if msvc {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        let def = std::path::Path::new(&dir).join("beezip_shell.def");
        println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def.display());
    }
}
