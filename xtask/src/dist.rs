//! `cargo xtask dist [--debug] [--version V]`: BeeZip's bundles for the platform it runs on: the
//! Windows installer (docs/M3.md §5.5, M4 §9), the Linux packages ([`linux`]) and the macOS app
//! and disk image ([`macos`], docs/M6.md §9.7). Each puts the CLI in its bundle, takes its file
//! associations from `formats.list` ([`associations`]), and with `TAURI_SIGNING_PRIVATE_KEY`
//! writes the updater's `latest.json` for its platform beside the signed bundles.
//!
//! On Windows:
//!
//! 1. The CLI and the Explorer menu's DLL are built into their own target dir,
//!    `target/dist-cli`, so the GUI's rename to `BeeZip.exe` can't clobber `beezip.exe` on a
//!    case-insensitive file system. The DLL is staged as `beezip_shell_<V>.dll`, a new name for
//!    each version, so an upgrade never has to replace a file Explorer has loaded.
//! 2. `target/dist/tauri.dist.json` is written from `packaging/windows/tauri.dist.json`, with the
//!    staged resources, the NSIS hooks and the file associations, which come from `formats.list`
//!    so the list has one source. It stays out of `tauri.conf.json` because tauri-build copies
//!    resources when the app compiles and fails on a missing one.
//! 3. `pnpm tauri build --bundles nsis --config target/dist/tauri.dist.json` builds the installer,
//!    with `CARGO_TARGET_DIR=target/dist`: the rename to `BeeZip.exe` in `target/debug` would
//!    replace the development `beezip.exe`, which Windows sees as the same file.
//! 4. The portable copy, `bundle/portable/BeeZip_<V>_x64-portable.zip` ([`portable`]): the same
//!    programs, to unzip and run. `latest.json` goes in `bundle/`, naming both.
//!
//! `--version V` builds the installer as version V (the workspace's otherwise), so the upgrade
//! check can build 0.1.0 and 0.1.1 from one tree.
//!
//! The Windows 11 menu's package goes in as well (M4 §9): `sparse\` holds its manifest, naming
//! this version's DLL, and its logos, which `beezip shell install --mode modern --dev` registers
//! under Developer Mode. A signed build also packs them into `beezip-sparse.msix` and signs it,
//! which the installer's `shell install` registers on Windows 11 where the certificate is
//! trusted. An unsigned `.msix` is never shipped: nothing can install it without admin.
//!
//! Signing (docs/M6.md §9.2, `sign.rs`): `BEEZIP_SIGN` is `none` (the default), `dev`
//! (`--sign-dev`: `xtask dev-cert`'s certificate), `pfx` or `artifact`. When it signs, Tauri
//! signs every file it builds through `packaging/windows/sign.ps1`, which also signs the
//! `nsExec.dll` Tauri leaves out; afterwards `dist` checks that each of them carries a signature.
//!
//! The updater (docs/M6.md §9.4) gets its public key from `packaging/updater.pub`, or from
//! `BEEZIP_UPDATER_PUBKEY`, which wins; without one the app never checks for updates. With
//! `TAURI_SIGNING_PRIVATE_KEY` set (and `…_PASSWORD`), Tauri also signs the installer for the
//! updater (`<setup>.exe.sig`), and `dist` writes `latest.json` beside it, for the GitHub release
//! of this version (§9.5). `BEEZIP_UPDATER_ENDPOINT` replaces the GitHub endpoint, for test
//! builds only: it may be `http://`.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use anyhow::{Context, bail};
use beezip_commands::shell::{MSIX, SPARSE};
use beezip_commands::{Engine, NonInteractive, discard_events, registry};
use serde_json::{Value, json};

use crate::codegen::workspace_root;
use crate::sign::{self, Mode};

mod linux;
mod macos;
mod portable;

/// The platform a bundle is for: always the one `dist` runs on, since each bundler runs only on
/// its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Linux,
    Mac,
}

impl Os {
    pub fn this() -> anyhow::Result<Self> {
        Ok(match std::env::consts::OS {
            "windows" => Self::Windows,
            "linux" => Self::Linux,
            "macos" => Self::Mac,
            other => bail!("BeeZip has no bundle for {other}"),
        })
    }

    /// Extensions this platform opens itself, which BeeZip doesn't take over. Explorer's menu
    /// still offers BeeZip's items for Windows' ones.
    fn owns(self) -> &'static [&'static str] {
        match self {
            Self::Windows => WINDOWS_OWNS,
            Self::Linux => linux::SYSTEM_OWNS,
            Self::Mac => macos::SYSTEM_OWNS,
        }
    }
}

/// Document formats BeeZip reads but leaves to their own apps: zip-based ones, and CHM help files.
const DOCUMENTS: &[&str] = &[
    "jar", "war", "apk", "aab", "ipa", "xpi", "vsix", "nupkg", "whl", "docx", "xlsx", "pptx",
    "odt", "ods", "odp", "epub", "appx", "msix",
    // A help file opens in the system's help viewer: HTML Help on Windows, a CHM viewer
    // elsewhere. BeeZip reads it itself since M9, but leaves it to them (docs/M9.md §7).
    "chm",
];

/// Extensions that only name a later part of a set; the first part is what people open.
const LATER_PARTS: &[&str] = &["r00"];

/// Extensions Windows opens itself: it mounts disk images (ISO, and VHD and VHDX, docs/M8.md
/// decision 6) and shows cabinets as folders, and taking those over would surprise people
/// (docs/M5.md §5.12). Explorer's menu still offers BeeZip's items for them.
const WINDOWS_OWNS: &[&str] = &["cab", "iso", "vhd", "vhdx"];

pub fn run(debug: bool, version: Option<&str>, sign_dev: bool) -> anyhow::Result<()> {
    let root = workspace_root();
    let version = version.unwrap_or(env!("CARGO_PKG_VERSION"));
    let os = Os::this()?;
    if sign_dev && os != Os::Windows {
        bail!("--sign-dev signs a Windows installer");
    }
    match os {
        Os::Windows => windows(&root, debug, version, sign_dev),
        Os::Linux => linux::run(&root, debug, version),
        Os::Mac => macos::run(&root, debug, version),
    }
}

/// `debug` or `release`.
pub fn profile(debug: bool) -> &'static str {
    if debug { "debug" } else { "release" }
}

/// Builds the CLI (and on Windows the Explorer menu's DLL) into `target/dist-cli`, apart from the
/// app's target dir, and returns the folder they're in.
fn build_cli(root: &Path, debug: bool, packages: &[&str]) -> anyhow::Result<PathBuf> {
    let mut cargo = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cargo.current_dir(root).args(["build", "--locked"]);
    for p in packages {
        cargo.args(["-p", p]);
    }
    cargo.arg("--target-dir").arg(root.join("target/dist-cli"));
    if !debug {
        cargo.arg("--release");
    }
    check(
        cargo.status(),
        &format!("cargo build -p {}", packages.join(" -p ")),
    )?;
    Ok(root.join("target/dist-cli").join(profile(debug)))
}

/// Writes Tauri's `--config` overlay to `path`, refusing a `null` anywhere in it.
fn write_overlay(config: &Value, path: &Path) -> anyhow::Result<()> {
    if let Some(at) = null_at(config, "") {
        bail!(
            "the config overlay has a null at {at}, which would delete that key from \
             tauri.conf.json"
        );
    }
    std::fs::write(path, serde_json::to_string_pretty(config)? + "\n")?;
    println!("wrote {}", path.display());
    Ok(())
}

/// The overlay template `packaging/<dir>/tauri.dist.json`.
fn template(root: &Path, dir: &str) -> anyhow::Result<Value> {
    let path = root.join("packaging").join(dir).join("tauri.dist.json");
    serde_json::from_str(
        &std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("reading {}", path.display()))
}

/// The Windows installer.
fn windows(root: &Path, debug: bool, version: &str, sign_dev: bool) -> anyhow::Result<()> {
    let root = root.to_path_buf();
    let profile = profile(debug);

    // Everything signing needs is checked before a build of several minutes.
    let env = |name: &str| std::env::var(name).ok();
    let mode = Mode::from_env(sign_dev, &env)?;
    let missing = mode.missing(&env);
    if !missing.is_empty() {
        bail!("BEEZIP_SIGN={} needs {}", mode.name(), missing.join(", "));
    }
    if mode == Mode::None {
        println!("an unsigned build (BEEZIP_SIGN=none): no Windows 11 menu package");
    } else {
        println!("a signed build (BEEZIP_SIGN={})", mode.name());
    }

    println!("building the CLI and the Explorer menu ({profile})");
    let built = build_cli(&root, debug, &["beezip-cli", "beezip-shell"])?;
    let cli = built.join(format!("beezip{}", std::env::consts::EXE_SUFFIX));
    let dll = built.join("beezip_shell.dll");
    for f in [&cli, &dll] {
        if !f.is_file() {
            bail!("{} wasn't built", f.display());
        }
    }

    // The CLI is signed first (Tauri would sign it in place anyway, and skips it once a trusted
    // signature is there), and the package's publisher is its signer's subject, exactly as
    // Windows writes it, which signtool demands of a package.
    let signer = if mode == Mode::None {
        None
    } else {
        sign::sign(&root, mode, &cli, None)?;
        sign::signer(&root, &cli)?
    };
    let publisher = sign::publisher(
        mode,
        env("BEEZIP_SIGN_PUBLISHER").as_deref(),
        signer.as_deref(),
    )?;
    if mode != Mode::None {
        println!("the Windows 11 menu's package is published by {publisher}");
    }

    let dir = root.join("target/dist");
    std::fs::create_dir_all(&dir)?;
    let sparse = dir.join(SPARSE);
    crate::sparse::stage(&root, &sparse, version, &dll_name(version), &publisher)?;
    let msix = if mode == Mode::None {
        None
    } else {
        let msix = dir.join(MSIX);
        crate::sparse::pack(&sparse, &msix)?;
        sign::sign(&root, mode, &msix, Some(&publisher))?;
        if !sign::msix_signed(&msix)? {
            bail!("{} isn't signed after sign.ps1", msix.display());
        }
        println!("packed and signed {}", msix.display());
        Some(msix)
    };
    let package = Package {
        sparse: &sparse,
        msix: msix.as_deref(),
    };
    let mut config = config(&root, &cli, &dll, version, &package)?;
    if mode != Mode::None {
        config["bundle"]["windows"]["signCommand"] = sign::sign_command(&root);
    }
    let config_path = dir.join("tauri.dist.json");
    write_overlay(&config, &config_path)?;

    let bundles = dir.join(profile).join("bundle");
    let bundle = bundles.join("nsis");
    let installer = bundle.join(installer_name(version));
    // A signature or update manifest from an earlier build would describe another installer.
    // (Before the portable copy, latest.json was written beside the installer.)
    for stale in [
        sig(&installer),
        bundle.join(LATEST_JSON),
        bundles.join(LATEST_JSON),
    ] {
        if stale.exists() {
            std::fs::remove_file(&stale)
                .with_context(|| format!("removing {}", stale.display()))?;
        }
    }

    println!("building the installer ({profile})");
    let mut tauri = pnpm();
    tauri
        .current_dir(root.join("apps/desktop"))
        .env("CARGO_TARGET_DIR", &dir)
        .args(["tauri", "build", "--bundles", "nsis", "--config"])
        .arg(&config_path);
    if debug {
        tauri.arg("--debug");
    }
    if mode != Mode::None {
        sign::environment(&mut tauri, mode);
    }
    check(tauri.status(), "pnpm tauri build")?;

    if !installer.is_file() {
        bail!("no installer at {}", installer.display());
    }
    if mode != Mode::None {
        let plugins = dir.join(profile).join("nsis/x64/Plugins/x86-unicode");
        check_signed(&[&installer, &cli, &dll], &plugins)?;
    }
    println!("installer: {}", installer.display());

    let programs = portable::Programs {
        app: &dir.join(profile).join("BeeZip.exe"),
        cli: &cli,
        dll: &dll,
    };
    let zip = portable::build(
        &root,
        &programs,
        version,
        mode,
        &dir.join("portable"),
        &bundles.join("portable"),
    )?;

    write_latest_json(
        version,
        &[
            Updatable {
                key: "windows-x86_64-nsis",
                file: &installer,
            },
            Updatable {
                key: portable::KEY,
                file: &zip,
            },
        ],
        &bundles,
    )?;
    Ok(())
}

/// A bundle the updater can install, and its key in `latest.json`'s `platforms`.
pub struct Updatable<'a> {
    pub key: &'a str,
    pub file: &'a Path,
}

/// `<file>.sig`, the updater's signature of `file`.
pub fn sig(file: &Path) -> PathBuf {
    let mut s = file.as_os_str().to_owned();
    s.push(".sig");
    s.into()
}

/// With the updater's signatures (`<file>.sig`, made when `TAURI_SIGNING_PRIVATE_KEY` is set),
/// writes `latest.json` into `dir` for the release of `version`: every bundle that has one.
/// Without any, there's nothing to write.
fn write_latest_json(version: &str, bundles: &[Updatable], dir: &Path) -> anyhow::Result<()> {
    let mut platforms = Vec::new();
    for b in bundles {
        let sig = sig(b.file);
        if !sig.is_file() {
            continue;
        }
        let signature =
            std::fs::read_to_string(&sig).with_context(|| format!("reading {}", sig.display()))?;
        let file = b
            .file
            .file_name()
            .context("a bundle without a name")?
            .to_string_lossy()
            .into_owned();
        println!("updater signature: {}", sig.display());
        platforms.push(crate::release::Platform {
            key: b.key.to_owned(),
            file,
            signature,
        });
    }
    if platforms.is_empty() {
        return Ok(());
    }
    let latest = crate::release::latest_json(
        version,
        &platforms,
        &crate::release::rfc3339(std::time::SystemTime::now()),
    );
    let path = dir.join(LATEST_JSON);
    std::fs::write(&path, serde_json::to_string_pretty(&latest)? + "\n")?;
    println!("update manifest: {}", path.display());
    Ok(())
}

/// The installer Tauri names for `version` (productName, version, arch).
pub fn installer_name(version: &str) -> String {
    format!("BeeZip_{version}_x64-setup.exe")
}

/// The updater's manifest, beside the installer (docs/M6.md §9.4).
pub const LATEST_JSON: &str = "latest.json";

/// The plugins of Tauri's own NSIS template, which Tauri signs in its copy, and `nsExec.dll`,
/// which hooks.nsh uses and sign.ps1 signs there.
const NSIS_PLUGINS: &[&str] = &[
    "NSISdl.dll",
    "StartMenu.dll",
    "System.dll",
    "nsDialogs.dll",
    "additional/nsis_tauri_utils.dll",
    "nsExec.dll",
];

/// After a signed build: every file Tauri signed carries a signature, nsExec.dll included. The
/// installer was built from `plugins`, Tauri's copy of NSIS's plugins, and the resources were
/// signed in place. (BeeZip.exe is signed only inside the installer: Tauri puts the unsigned
/// build back afterwards.)
fn check_signed(files: &[&Path], plugins: &Path) -> anyhow::Result<()> {
    if !plugins.is_dir() {
        bail!(
            "Tauri's copy of NSIS's plugins isn't at {}, so nsExec.dll's signature can't be \
             checked: has the bundler changed? (packaging/windows/sign.ps1 signs it there)",
            plugins.display()
        );
    }
    let plugins: Vec<PathBuf> = NSIS_PLUGINS.iter().map(|p| plugins.join(p)).collect();
    let mut unsigned = Vec::new();
    for file in files
        .iter()
        .copied()
        .chain(plugins.iter().map(PathBuf::as_path))
    {
        if !sign::pe_signed(file)? {
            unsigned.push(file.display().to_string());
        }
    }
    if !unsigned.is_empty() {
        bail!("signed build, but unsigned: {}", unsigned.join(", "));
    }
    println!(
        "signed: the installer, the CLI, the menu's DLL and NSIS's {} plugins",
        NSIS_PLUGINS.len()
    );
    Ok(())
}

pub fn check(status: std::io::Result<std::process::ExitStatus>, what: &str) -> anyhow::Result<()> {
    let status = status.with_context(|| format!("starting {what}"))?;
    if !status.success() {
        bail!("{what} failed: {status}");
    }
    Ok(())
}

/// pnpm is a `.cmd` shim on Windows, which `Command` doesn't look for.
pub fn pnpm() -> Command {
    if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/d", "/c", "pnpm"]);
        c
    } else {
        Command::new("pnpm")
    }
}

/// Forward slashes, which Tauri's config and NSIS both take.
fn slashes(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

/// The DLL's name in the install folder.
pub fn dll_name(version: &str) -> String {
    format!("beezip_shell_{version}.dll")
}

/// The Windows 11 menu's package, staged: the manifest's folder, and the signed `.msix`.
struct Package<'a> {
    sparse: &'a Path,
    msix: Option<&'a Path>,
}

fn config(
    root: &Path,
    cli: &Path,
    dll: &Path,
    version: &str,
    package: &Package,
) -> anyhow::Result<Value> {
    let mut config = template(root, "windows")?;
    let bundle = config
        .get_mut("bundle")
        .context("the template has no `bundle`")?;
    let mut resources = serde_json::Map::new();
    resources.insert(slashes(cli), json!("bin/beezip.exe"));
    resources.insert(slashes(dll), json!(dll_name(version)));
    resources.insert(
        slashes(&root.join("THIRD_PARTY_NOTICES.md")),
        json!("THIRD_PARTY_NOTICES.md"),
    );
    for entry in std::fs::read_dir(package.sparse)? {
        let path = entry?.path();
        let name = path.file_name().context("a staged file without a name")?;
        resources.insert(
            slashes(&path),
            json!(format!("{SPARSE}/{}", name.to_string_lossy())),
        );
    }
    if let Some(msix) = package.msix {
        resources.insert(slashes(msix), json!(MSIX));
    }
    bundle["resources"] = Value::Object(resources);
    let associations = associations(Os::Windows)?;
    let hooks = hooks(root, &associations, version)?;
    bundle["fileAssociations"] = Value::Array(associations);
    bundle["windows"]["nsis"]["installerHooks"] = json!(slashes(&hooks));
    config["version"] = json!(version);
    updater(root, &mut config, &|name| std::env::var(name).ok())?;
    Ok(config)
}

/// The path of a `null` in `value`, if it has one. Tauri merges `--config` files into
/// tauri.conf.json as a JSON merge patch (RFC 7386), where a `null` deletes the key it names.
fn null_at(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::Null => Some(if path.is_empty() {
            "the top".into()
        } else {
            path.into()
        }),
        Value::Object(map) => map
            .iter()
            .find_map(|(k, v)| null_at(v, &format!("{path}/{k}"))),
        Value::Array(list) => list
            .iter()
            .enumerate()
            .find_map(|(i, v)| null_at(v, &format!("{path}/{i}"))),
        _ => None,
    }
}

/// Where the updater's public key is kept, once there is one (docs/M6.md §14).
pub const UPDATER_PUBKEY: &str = "packaging/updater.pub";

/// The updater's part of the config: the public key, a test endpoint, and whether Tauri signs
/// the installer for the updater. `env` reads an environment variable.
fn updater(
    root: &Path,
    config: &mut Value,
    env: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<()> {
    let set = |v: Option<String>| v.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
    let file = root.join(UPDATER_PUBKEY);
    let pubkey = match set(env("BEEZIP_UPDATER_PUBKEY")) {
        Some(key) => Some(key),
        None if file.is_file() => set(Some(
            std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?,
        )),
        None => None,
    };
    let signs = set(env("TAURI_SIGNING_PRIVATE_KEY")).is_some();
    // Only what's set goes in: Tauri merges this file into tauri.conf.json as a JSON merge
    // patch, where a `null` deletes the key, and an app without `plugins.updater` doesn't start.
    let mut updater = serde_json::Map::new();
    match &pubkey {
        Some(key) => {
            updater.insert("pubkey".into(), json!(key));
            println!("the updater checks for updates");
        }
        None if signs => bail!(
            "TAURI_SIGNING_PRIVATE_KEY is set, but there's no public key in {UPDATER_PUBKEY} \
             or BEEZIP_UPDATER_PUBKEY"
        ),
        None => println!("no updater key ({UPDATER_PUBKEY}): this build never checks for updates"),
    }
    if let Some(endpoint) = set(env("BEEZIP_UPDATER_ENDPOINT")) {
        updater.insert(
            "dangerousInsecureTransportProtocol".into(),
            json!(endpoint.starts_with("http:")),
        );
        updater.insert("endpoints".into(), json!([endpoint]));
        println!("test build: the updater asks {endpoint}");
    }
    if !updater.is_empty() {
        config["plugins"]["updater"] = Value::Object(updater);
    }
    if signs {
        config["bundle"]["createUpdaterArtifacts"] = json!(true);
        println!("signing the installer for the updater");
    }
    Ok(())
}

/// `target/dist/hooks.nsh`: the DLL's name, `packaging/windows/hooks.nsh`, and the list of
/// associations its hooks walk.
fn hooks(root: &Path, associations: &[Value], version: &str) -> anyhow::Result<PathBuf> {
    let template = root.join("packaging/windows/hooks.nsh");
    let mut text = format!(
        "; Generated by `cargo xtask dist`: the Explorer menu's DLL in this version.\n\
         !define BEEZIP_SHELL_DLL \"{}\"\n\n",
        dll_name(version)
    );
    text.push_str(
        &std::fs::read_to_string(&template)
            .with_context(|| format!("reading {}", template.display()))?,
    );
    text.push_str("\n; Generated by `cargo xtask dist` from formats.list.\n");
    text.push_str("!macro BEEZIP_FOR_EACH_ASSOCIATION MACRO\n");
    for a in associations {
        let ext = a["ext"][0]
            .as_str()
            .context("an association without an extension")?;
        let class = a["name"]
            .as_str()
            .context("an association without a name")?;
        text.push_str(&format!(
            "  !insertmacro ${{MACRO}} \"{ext}\" \"{class}\"\n"
        ));
    }
    text.push_str("!macroend\n");
    let path = root.join("target/dist/hooks.nsh");
    std::fs::create_dir_all(root.join("target/dist"))?;
    std::fs::write(&path, text)?;
    Ok(path)
}

/// One association per extension, `BeeZip.<ext>`, from `formats.list`: every archive and
/// compressed-file extension BeeZip reads, but not the document formats, later parts, or what
/// `os` opens itself, plus `.001` for numbered volume sets. On Linux each carries its MIME type
/// ([`linux::mime_type`]); on macOS its name is its description, and it carries its content type
/// where macOS declares one ([`macos::content_type`]).
pub fn associations(os: Os) -> anyhow::Result<Vec<Value>> {
    let formats = Engine::new(registry())
        .invoke(
            "formats.list",
            json!({}),
            Arc::new(NonInteractive),
            discard_events(),
        )
        .map_err(|e| anyhow::anyhow!("formats.list: {}", e.message))?
        .join()
        .map_err(|e| anyhow::anyhow!("formats.list: {}", e.message))?;
    let mut by_ext: BTreeMap<String, String> = BTreeMap::new();
    let mut add = |list: &Value, what: String| {
        for e in list
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let ext = e.trim_start_matches('.').to_ascii_lowercase();
            if ext.is_empty()
                || DOCUMENTS.contains(&ext.as_str())
                || LATER_PARTS.contains(&ext.as_str())
                || os.owns().contains(&ext.as_str())
            {
                continue;
            }
            by_ext.entry(ext).or_insert_with(|| what.clone());
        }
    };
    for f in formats["formats"].as_array().into_iter().flatten() {
        // The formats BeeZip reads but leaves out of Explorer's menu aren't associated: `.img`,
        // `.msi`, `.exe` (docs/M6.md §3.7, docs/M7.md §9).
        if f["caps"]["list"] == true && f["menu"] == true {
            // "ZIP archive", but "Apple disk image" and "Debian package" as they are.
            let name = f["name"].as_str().unwrap_or("");
            let what = if name.ends_with(" image") || name.ends_with(" package") {
                name.to_owned()
            } else {
                format!("{name} archive")
            };
            add(&f["extensions"], what);
        }
    }
    for c in formats["codecs"].as_array().into_iter().flatten() {
        add(
            &c["extensions"],
            format!("{} compressed file", c["name"].as_str().unwrap_or("")),
        );
    }
    by_ext.insert("001".into(), "Split archive, first part".into());
    let mut list = Vec::new();
    for (ext, description) in by_ext {
        let mut a = json!({
            "ext": [ext],
            "name": format!("BeeZip.{ext}"),
            "description": description,
            "role": "Editor",
        });
        match os {
            Os::Windows => {}
            Os::Linux => {
                if let Some(mime) = linux::mime_type(&ext) {
                    a["mimeType"] = json!(mime);
                }
            }
            Os::Mac => {
                a["name"] = a["description"].clone();
                if let Some(uti) = macos::content_type(&ext) {
                    a["contentTypes"] = json!([uti]);
                }
            }
        }
        list.push(a);
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn associations_cover_the_archives_but_not_documents() {
        let list = associations(Os::Windows).unwrap();
        let exts: Vec<&str> = list.iter().map(|a| a["ext"][0].as_str().unwrap()).collect();
        for want in [
            "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "tzst",
            "lz", "tlz", "lzma", "lz4", "br", "sz", "cbz", "cb7", "cbr", "001", "cpio", "ar",
            "deb", "udeb", "rpm", "lzh", "lha", "z", "taz", "lzo", "tzo", "arj", "ace", "cba",
            "zoo", "arc", "pkg", "mpkg", "xar", "vmdk", "qcow2", "vdi",
            // BeeZip's own since M8 (docs/M8.md decision 6).
            "wim", "esd", "swm",
        ] {
            assert!(exts.contains(&want), "{want} is missing from {exts:?}");
        }
        for not in [
            "docx", "jar", "epub", "r00", "cab", "iso", "a", "lib", "vhd", "vhdx", "img", "msi",
            "chm",
        ] {
            assert!(!exts.contains(&not), "{not} shouldn't be associated");
        }
        assert_eq!(list[0]["name"], format!("BeeZip.{}", exts[0]));
    }

    #[test]
    fn the_updater_takes_its_key_from_the_environment_first() {
        let dir = tempfile::tempdir().unwrap();
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                vars.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        // No key anywhere: the config is left alone, and signing for the updater is refused.
        let mut config = json!({ "bundle": {} });
        updater(dir.path(), &mut config, &env(&[])).unwrap();
        assert_eq!(
            config,
            json!({ "bundle": {} }),
            "nothing added, not even a null"
        );
        assert_eq!(null_at(&config, ""), None);
        assert_eq!(
            null_at(&json!({ "plugins": { "updater": null } }), ""),
            Some("/plugins/updater".into())
        );
        assert!(
            updater(
                dir.path(),
                &mut config,
                &env(&[("TAURI_SIGNING_PRIVATE_KEY", "k")])
            )
            .is_err()
        );

        std::fs::create_dir_all(dir.path().join("packaging")).unwrap();
        std::fs::write(dir.path().join(UPDATER_PUBKEY), "from-the-file\n").unwrap();
        let mut config = json!({ "bundle": {} });
        updater(dir.path(), &mut config, &env(&[])).unwrap();
        assert_eq!(config["plugins"]["updater"]["pubkey"], "from-the-file");
        assert_eq!(config["bundle"]["createUpdaterArtifacts"], Value::Null);

        let mut config = json!({ "bundle": {} });
        let vars = env(&[
            ("BEEZIP_UPDATER_PUBKEY", "from-the-env"),
            (
                "BEEZIP_UPDATER_ENDPOINT",
                "http://127.0.0.1:8765/latest.json",
            ),
            ("TAURI_SIGNING_PRIVATE_KEY", "k"),
        ]);
        updater(dir.path(), &mut config, &vars).unwrap();
        let u = &config["plugins"]["updater"];
        assert_eq!(u["pubkey"], "from-the-env");
        assert_eq!(u["endpoints"], json!(["http://127.0.0.1:8765/latest.json"]));
        assert_eq!(u["dangerousInsecureTransportProtocol"], true);
        assert_eq!(config["bundle"]["createUpdaterArtifacts"], true);
    }
}
