//! `cargo xtask dist` on Linux (docs/M6.md §9.7): the deb, the rpm and the AppImage, each with
//! the CLI as `/usr/bin/beezip`, BeeZip's MIME package and the third-party notices.
//!
//! 1. The CLI is built into `target/dist-cli`, as on Windows.
//! 2. `target/dist/` gets the desktop entry, from `packaging/linux/beezip.desktop` with the MIME
//!    types filled in; `beezip.xml`, the MIME package for the extensions shared-mime-info doesn't
//!    know ([`GLOBS`]); and `tauri.dist.json`, the overlay from `packaging/linux/tauri.dist.json`
//!    with the files, the desktop entry and the associations.
//! 3. `pnpm tauri build --bundles deb,rpm,appimage --config target/dist/tauri.dist.json`, with
//!    `CARGO_TARGET_DIR=target/dist`.
//! 4. With `TAURI_SIGNING_PRIVATE_KEY`, Tauri signs each bundle for the updater (`<bundle>.sig`),
//!    and `latest.json` goes beside them in `target/dist/<profile>/bundle/`, under the updater's
//!    keys for each kind of bundle ([`BUNDLES`]).
//!
//! The package is `beezip` (`productName`: Tauri names the deb and rpm packages
//! kebab-case(productName), which would be `bee-zip`); the window's title and the desktop entry's
//! `Name` stay "BeeZip". The desktop entry is BeeZip's own because Tauri's template has no `%F`
//! in `Exec` (tauri-bundler 2.10.4), so opening an associated file would start BeeZip without
//! it. Debian's and Fedora's shared-mime-info and desktop-file-utils rebuild their caches when a
//! package adds to `/usr/share/mime/packages` or `/usr/share/applications` (dpkg triggers, rpm
//! file triggers), so the packages need no scripts for them; the rpm has one only to remove its
//! doc folder ([`RPM_POSTUN`]).
//!
//! Build on the oldest glibc the bundles should run on: binaries built against glibc 2.39 carry
//! weak `GLIBC_2.39` references from Rust's std (`pidfd_spawnp`, `pidfd_getpid`), which an older
//! loader warns about on every start; and the libraries inside the AppImage need at least the
//! build system's glibc (one built on 24.04 doesn't start on 22.04). Built on Ubuntu 22.04
//! (glibc 2.35), the deb and the AppImage run on 22.04, Debian 12 and 24.04 without a warning.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde_json::{Value, json};

use super::{
    Os, Updatable, build_cli, check, pnpm, profile, slashes, template, updater, write_latest_json,
    write_overlay,
};

/// Extensions Linux desktops open themselves: package installers take `.deb`, `.rpm` and
/// `.snap` (Ubuntu's App Center installs a `.snap` it's given), the disk image mounter `.iso`,
/// and the virtual machine apps (GNOME Boxes, virt-manager) the virtual disks BeeZip reads from
/// M8 (docs/M8.md §16).
pub const SYSTEM_OWNS: &[&str] = &[
    "deb", "udeb", "rpm", "snap", "iso", "vhd", "vhdx", "vmdk", "qcow2", "qcow", "vdi",
];

/// Associated on Windows and macOS, but not here, for want of a MIME type: `.001` is the first
/// part of anything split, and the desktop types such a file by its content instead, so a
/// `x.7z.001` is `application/x-7z-compressed`, which BeeZip claims. A glob would outrank that.
/// WIM's (`.wim`, `.esd`, `.swm`, BeeZip's own from M8) have no type BeeZip relies on yet.
pub const LEFT_OUT: &[&str] = &["001", "wim", "esd", "swm"];

/// Each associated extension's MIME type: shared-mime-info's for `*.<ext>` (Ubuntu 24.04's
/// shared-mime-info 2.4, matched by glob), or for the extensions in [`GLOBS`] the type BeeZip's
/// MIME package gives them. Where shared-mime-info reads an extension differently from BeeZip
/// (`*.tlz` is tar with LZMA there, tar with lzip here; `*.tbz` tar with bzip1), it keeps its own
/// name for the type: that's what the desktop calls the file, and BeeZip reads it by its content.
const MIME: &[(&str, &str)] = &[
    ("7z", "application/x-7z-compressed"),
    ("ace", "application/x-ace"),
    ("ar", "application/x-archive"),
    ("arc", "application/x-arc"),
    ("arj", "application/x-arj"),
    ("br", "application/x-brotli"),
    ("bz2", "application/x-bzip2"),
    ("cab", "application/vnd.ms-cab-compressed"),
    ("cb7", "application/x-cb7"),
    ("cba", "application/x-cba"),
    ("cbr", "application/vnd.comicbook-rar"),
    ("cbz", "application/vnd.comicbook+zip"),
    ("cpio", "application/x-cpio"),
    ("dmg", "application/x-apple-diskimage"),
    ("gz", "application/gzip"),
    ("lha", "application/x-lha"),
    ("lz", "application/x-lzip"),
    ("lz4", "application/x-lz4"),
    ("lzh", "application/x-lha"),
    ("lzma", "application/x-lzma"),
    ("lzo", "application/x-lzop"),
    ("mpkg", "application/x-xar"),
    ("pkg", "application/x-xar"),
    ("rar", "application/vnd.rar"),
    ("sqfs", "application/vnd.squashfs"),
    ("squashfs", "application/vnd.squashfs"),
    ("sz", "application/x-snappy-framed"),
    ("tar", "application/x-tar"),
    ("taz", "application/x-tarz"),
    ("tbz", "application/x-bzip1-compressed-tar"),
    ("tbz2", "application/x-bzip2-compressed-tar"),
    ("tgz", "application/x-compressed-tar"),
    ("tlz", "application/x-lzma-compressed-tar"),
    ("txz", "application/x-xz-compressed-tar"),
    ("tzo", "application/x-tzo"),
    ("tzst", "application/x-zstd-compressed-tar"),
    ("xar", "application/x-xar"),
    ("xz", "application/x-xz"),
    ("z", "application/x-compress"),
    ("zip", "application/zip"),
    ("zlib", "application/zlib"),
    ("zoo", "application/x-zoo"),
    ("zst", "application/zstd"),
    ("zstd", "application/zstd"),
    ("zz", "application/zlib"),
];

/// The extensions shared-mime-info has no glob for, which BeeZip's MIME package
/// (`/usr/share/mime/packages/beezip.xml`) adds: to shared-mime-info's own type for the format
/// where it has one (ARC, squashfs, zlib, Zstandard, XAR), otherwise to one of [`NEW_TYPES`].
const GLOBS: &[&str] = &[
    "arc", "br", "cba", "mpkg", "sqfs", "squashfs", "sz", "zlib", "zstd",
];

/// The types BeeZip's MIME package defines, which shared-mime-info doesn't have: the type, its
/// description, and the type it's a kind of. `file --mime-type` names Snappy's framed format so
/// (libmagic knows no Brotli: it has no signature); `x-cba` follows shared-mime-info's `x-cb7`.
const NEW_TYPES: &[(&str, &str, Option<&str>)] = &[
    ("application/x-brotli", "Brotli compressed file", None),
    (
        "application/x-cba",
        "Comic book archive (ACE container)",
        Some("application/x-ace"),
    ),
    (
        "application/x-snappy-framed",
        "Snappy compressed file",
        None,
    ),
];

/// Types the desktop entry claims besides the associations': tarballs known only by a double
/// extension (`*.tar.lz`, `*.tar.lz4`), which have no shorthand of their own to associate.
const MORE_TYPES: &[&str] = &[
    "application/x-lz4-compressed-tar",
    "application/x-lzip-compressed-tar",
];

/// The names an older shared-mime-info gives the same files: 2.1 (Ubuntu 22.04) and 2.2 (Debian
/// 12) call `*.bz2` `application/x-bzip` and every bzip'd tarball
/// `application/x-bzip-compressed-tar`, which 2.4 keeps as aliases. The desktop entry claims
/// both names, since a desktop matches the name its own database gives a file.
const OLDER_NAMES: &[(&str, &str)] = &[
    ("application/x-bzip2", "application/x-bzip"),
    (
        "application/x-bzip2-compressed-tar",
        "application/x-bzip-compressed-tar",
    ),
    (
        "application/x-bzip1-compressed-tar",
        "application/x-bzip-compressed-tar",
    ),
];

/// `mime`'s name in an older shared-mime-info, if it had another.
fn older_name(mime: &str) -> Option<&'static str> {
    OLDER_NAMES
        .iter()
        .find(|(new, _)| *new == mime)
        .map(|(_, old)| *old)
}

/// The desktop entry's template, with `@MIME_TYPES@` for the list xtask fills in. Tauri fills in
/// the rest (`{{exec}}`, `{{icon}}`).
const DESKTOP: &str = "packaging/linux/beezip.desktop";
const MIME_TYPES: &str = "@MIME_TYPES@";

/// The package's name, and its folder under `/usr/share/doc`.
const PACKAGE: &str = "beezip";

/// The bundles Tauri builds, under `target/dist/<profile>/bundle/`, and the updater's key for
/// each (tauri-plugin-updater 2.14.1 looks for `linux-x86_64-<bundle type>`, then
/// `linux-x86_64`). The generic key is left out: a binary whose bundle type Tauri couldn't patch
/// in would take the AppImage, and the plugin installs that over the running executable.
pub const BUNDLES: &[(&str, &str)] = &[
    ("linux-x86_64-deb", "deb/{name}_{version}_amd64.deb"),
    ("linux-x86_64-rpm", "rpm/{name}-{version}-1.x86_64.rpm"),
    (
        "linux-x86_64-appimage",
        "appimage/{name}_{version}_amd64.AppImage",
    ),
];

/// `ext`'s MIME type.
pub fn mime_type(ext: &str) -> Option<&'static str> {
    MIME.iter().find(|(e, _)| *e == ext).map(|(_, m)| *m)
}

/// The Linux associations: [`super::associations`] without [`LEFT_OUT`], each with its MIME
/// type. Refused if one has none, before a build of several minutes.
pub fn associations() -> anyhow::Result<Vec<Value>> {
    let mut list = super::associations(Os::Linux)?;
    list.retain(|a| !LEFT_OUT.contains(&a["ext"][0].as_str().unwrap_or("")));
    let missing: Vec<&str> = list
        .iter()
        .filter(|a| a["mimeType"].as_str().is_none())
        .filter_map(|a| a["ext"][0].as_str())
        .collect();
    if !missing.is_empty() {
        bail!(
            "no MIME type for .{} (MIME in xtask/src/dist/linux.rs): every Linux association \
             needs one",
            missing.join(", .")
        );
    }
    Ok(list)
}

/// The desktop entry's `MimeType` list: every association's type once, [`MORE_TYPES`], and
/// their [`OLDER_NAMES`].
fn mime_types(associations: &[Value]) -> Vec<String> {
    let mut types: BTreeSet<&str> = associations
        .iter()
        .filter_map(|a| a["mimeType"].as_str())
        .chain(MORE_TYPES.iter().copied())
        .collect();
    let older: Vec<&str> = types.iter().filter_map(|t| older_name(t)).collect();
    types.extend(older);
    types.into_iter().map(str::to_owned).collect()
}

/// The desktop entry's template with the MIME types filled in.
fn desktop_entry(template: &str, types: &[String]) -> anyhow::Result<String> {
    if !template.contains(MIME_TYPES) {
        bail!("{DESKTOP} has no {MIME_TYPES} for the MIME types");
    }
    Ok(template.replace(MIME_TYPES, &format!("{};", types.join(";"))))
}

/// `beezip.xml`, shared-mime-info's format: the globs of [`GLOBS`], on their types, and
/// [`NEW_TYPES`] defined.
fn mime_package() -> anyhow::Result<String> {
    let mut by_type: Vec<(&str, Vec<&str>)> = Vec::new();
    for ext in GLOBS {
        let mime = mime_type(ext).with_context(|| format!(".{ext} is in GLOBS but not MIME"))?;
        match by_type.iter_mut().find(|(t, _)| *t == mime) {
            Some((_, exts)) => exts.push(ext),
            None => by_type.push((mime, vec![ext])),
        }
    }
    by_type.sort();
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!-- Generated by `cargo xtask dist` (xtask/src/dist/linux.rs): the file extensions BeeZip\n     \
         opens that shared-mime-info has no glob for. -->\n\
         <mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">\n",
    );
    for (mime, exts) in by_type {
        xml.push_str(&format!("  <mime-type type=\"{mime}\">\n"));
        if let Some((_, comment, parent)) = NEW_TYPES.iter().find(|(t, ..)| *t == mime) {
            xml.push_str(&format!("    <comment>{comment}</comment>\n"));
            if let Some(parent) = parent {
                xml.push_str(&format!("    <sub-class-of type=\"{parent}\"/>\n"));
            }
            xml.push_str("    <generic-icon name=\"package-x-generic\"/>\n");
        }
        for ext in exts {
            xml.push_str(&format!("    <glob pattern=\"*.{ext}\"/>\n"));
        }
        xml.push_str("  </mime-type>\n");
    }
    xml.push_str("</mime-info>\n");
    Ok(xml)
}

/// What goes in every bundle beside the app: the CLI, the MIME package and the notices.
fn files(staged: &Staged) -> Value {
    json!({
        "/usr/bin/beezip": slashes(&staged.cli),
        "/usr/share/mime/packages/beezip.xml": slashes(&staged.mime_xml),
        format!("/usr/share/doc/{PACKAGE}/{NOTICES}"): slashes(&staged.notices),
    })
}

/// The overlay: `packaging/linux/tauri.dist.json` with the version, the files, the desktop
/// entry, the associations and the updater's part.
fn config(
    root: &Path,
    staged: &Staged,
    associations: Vec<Value>,
    version: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<Value> {
    let mut config = template(root, "linux")?;
    if config["productName"] != PACKAGE {
        bail!("packaging/linux/tauri.dist.json's productName should be {PACKAGE}");
    }
    config["version"] = json!(version);
    let files = files(staged);
    let linux = &mut config["bundle"]["linux"];
    for kind in ["deb", "rpm", "appimage"] {
        linux[kind]["files"] = files.clone();
    }
    // The AppImage takes the deb's desktop entry.
    for kind in ["deb", "rpm"] {
        linux[kind]["desktopTemplate"] = json!(slashes(&staged.desktop));
    }
    // dpkg removes the folders it made; rpm only what the package lists, files only here.
    linux["rpm"]["postRemoveScript"] = json!(slashes(&root.join(RPM_POSTUN)));
    // wimlib's library, which BeeZip loads to read LZMS (docs/M11.md §6.2): recommended, not
    // required. Ubuntu 24.04 and Debian 13 name it libwim15t64; rpm finds it by its soname.
    linux["deb"]["recommends"] = json!([WIMLIB_DEB]);
    linux["rpm"]["recommends"] = json!([WIMLIB_RPM]);
    config["bundle"]["fileAssociations"] = Value::Array(associations);
    updater(root, &mut config, env)?;
    Ok(config)
}

/// The CLI, and the files `dist` writes for Tauri in `target/dist`.
struct Staged {
    cli: PathBuf,
    desktop: PathBuf,
    mime_xml: PathBuf,
    notices: PathBuf,
}

const NOTICES: &str = "THIRD_PARTY_NOTICES.md";

/// The package that holds wimlib's library, by its Debian names, and its soname for rpm.
const WIMLIB_DEB: &str = "libwim15t64 | libwim15";
const WIMLIB_RPM: &str = "libwim.so.15()(64bit)";

/// The rpm's `%postun`, which removes `/usr/share/doc/beezip`: Tauri's rpm owns the files in
/// `bundle.linux.rpm.files` but not their folders (tauri-bundler 2.10.4).
const RPM_POSTUN: &str = "packaging/linux/rpm-postun.sh";

/// Writes the desktop entry, the MIME package and a copy of the notices into `dir`, readable by
/// all and writable by the owner only: the rpm takes each file's mode as it finds it, and a
/// checkout's can be anything (0777 on a Windows folder mounted into Docker).
fn stage(root: &Path, dir: &Path, cli: PathBuf, associations: &[Value]) -> anyhow::Result<Staged> {
    let write = |name: &str, contents: &[u8]| -> anyhow::Result<PathBuf> {
        let path = dir.join(name);
        // A copy from an earlier build may be read-only.
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
        std::fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        }
        Ok(path)
    };
    let template = std::fs::read_to_string(root.join(DESKTOP))
        .with_context(|| format!("reading {DESKTOP}"))?;
    let desktop = write(
        "beezip.desktop",
        desktop_entry(&template, &mime_types(associations))?.as_bytes(),
    )?;
    let mime_xml = write("beezip.xml", mime_package()?.as_bytes())?;
    let notices =
        std::fs::read(root.join(NOTICES)).with_context(|| format!("reading {NOTICES}"))?;
    let notices = write(NOTICES, &notices)?;
    Ok(Staged {
        cli,
        desktop,
        mime_xml,
        notices,
    })
}

/// The bundles of `version`, under `bundle`, with their updater keys.
fn bundles(bundle: &Path, version: &str) -> Vec<(&'static str, PathBuf)> {
    BUNDLES
        .iter()
        .map(|(key, path)| {
            let path = path
                .replace("{name}", PACKAGE)
                .replace("{version}", version);
            (*key, bundle.join(path))
        })
        .collect()
}

pub fn run(root: &Path, debug: bool, version: &str) -> anyhow::Result<()> {
    let profile = profile(debug);
    let associations = associations()?;

    println!("building the CLI ({profile})");
    let cli = build_cli(root, debug, &["beezip-cli"])?.join("beezip");
    if !cli.is_file() {
        bail!("{} wasn't built", cli.display());
    }

    let dir = root.join("target/dist");
    std::fs::create_dir_all(&dir)?;
    let staged = stage(root, &dir, cli, &associations)?;
    let config = config(root, &staged, associations, version, &|name| {
        std::env::var(name).ok()
    })?;
    let config_path = dir.join("tauri.dist.json");
    write_overlay(&config, &config_path)?;

    let bundle = dir.join(profile).join("bundle");
    let bundles = bundles(&bundle, version);
    // A signature or update manifest from an earlier build would describe other bundles.
    let mut stale: Vec<PathBuf> = bundles
        .iter()
        .map(|(_, file)| {
            let mut sig = file.as_os_str().to_owned();
            sig.push(".sig");
            PathBuf::from(sig)
        })
        .collect();
    stale.push(bundle.join(super::LATEST_JSON));
    for f in stale.iter().filter(|f| f.exists()) {
        std::fs::remove_file(f).with_context(|| format!("removing {}", f.display()))?;
    }

    println!("building the deb, the rpm and the AppImage ({profile})");
    let mut tauri = pnpm();
    tauri
        .current_dir(root.join("apps/desktop"))
        .env("CARGO_TARGET_DIR", &dir)
        .args([
            "tauri",
            "build",
            "--bundles",
            "deb,rpm,appimage",
            "--config",
        ])
        .arg(&config_path);
    if debug {
        tauri.arg("--debug");
    }
    check(tauri.status(), "pnpm tauri build")?;

    for (_, file) in &bundles {
        let size = std::fs::metadata(file)
            .with_context(|| format!("no bundle at {}", file.display()))?
            .len();
        println!("{} ({:.1} MB)", file.display(), size as f64 / 1e6);
    }
    let updatable: Vec<Updatable> = bundles
        .iter()
        .map(|(key, file)| Updatable { key, file })
        .collect();
    write_latest_json(version, &updatable, &bundle)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn every_linux_association_has_a_mime_type_and_the_table_nothing_stale() {
        let list = associations().unwrap();
        let exts: Vec<&str> = list.iter().map(|a| a["ext"][0].as_str().unwrap()).collect();
        for a in &list {
            assert_eq!(
                a["mimeType"].as_str(),
                mime_type(a["ext"][0].as_str().unwrap())
            );
        }
        for (ext, _) in MIME {
            assert!(exts.contains(ext), ".{ext} is in MIME but isn't associated");
        }
        for ext in GLOBS {
            assert!(mime_type(ext).is_some(), ".{ext} is in GLOBS but not MIME");
        }
        for not in SYSTEM_OWNS.iter().chain(LEFT_OUT) {
            assert!(!exts.contains(not), ".{not} shouldn't be associated");
        }
        for want in [
            "zip", "7z", "rar", "tar", "tgz", "tlz", "zst", "cbz", "xar", "dmg",
        ] {
            assert!(exts.contains(&want), ".{want} is missing from {exts:?}");
        }
        // The extensions on Windows are here too, but for what Linux opens itself or can't type.
        let windows = crate::dist::associations(Os::Windows).unwrap();
        for a in &windows {
            let ext = a["ext"][0].as_str().unwrap();
            assert!(
                exts.contains(&ext) || SYSTEM_OWNS.contains(&ext) || LEFT_OUT.contains(&ext),
                ".{ext} is associated on Windows but not on Linux"
            );
        }
        // Every new type has a glob, and its parent is a type shared-mime-info has.
        for (mime, _, parent) in NEW_TYPES {
            assert!(
                GLOBS.iter().any(|e| mime_type(e) == Some(mime)),
                "{mime} has no glob"
            );
            if let Some(parent) = parent {
                assert!(MIME.iter().any(|(_, m)| m == parent));
            }
        }
    }

    #[test]
    fn the_desktop_entry_claims_every_type_once() {
        let root = crate::codegen::workspace_root();
        let template = std::fs::read_to_string(root.join(DESKTOP)).unwrap();
        let types = mime_types(&associations().unwrap());
        let entry = desktop_entry(&template, &types).unwrap();
        let line = entry
            .lines()
            .find_map(|l| l.strip_prefix("MimeType="))
            .unwrap();
        let listed: Vec<&str> = line.trim_end_matches(';').split(';').collect();
        let unique: BTreeSet<&str> = listed.iter().copied().collect();
        assert_eq!(listed.len(), unique.len(), "a type twice in {line}");
        for t in [
            "application/zip",
            "application/x-xar",
            "application/x-lha",
            "application/x-bzip2",
            "application/x-bzip",
            "application/x-bzip-compressed-tar",
            "application/x-lzip-compressed-tar",
            "application/x-brotli",
        ] {
            assert!(unique.contains(t), "{t} isn't in {line}");
        }
        let exec = entry.lines().find(|l| l.starts_with("Exec=")).unwrap();
        assert!(exec.ends_with(" %F"), "{exec}: files must reach BeeZip");
        assert!(entry.contains("\nName=BeeZip\n"));
        assert!(desktop_entry("[Desktop Entry]\n", &types).is_err());
    }

    #[test]
    fn the_mime_package_adds_the_globs_shared_mime_info_lacks() {
        let xml = mime_package().unwrap();
        for ext in GLOBS {
            assert!(
                xml.contains(&format!("<glob pattern=\"*.{ext}\"/>")),
                "{ext}"
            );
        }
        assert_eq!(xml.matches("<glob ").count(), GLOBS.len());
        assert_eq!(xml.matches("<comment>").count(), NEW_TYPES.len());
        assert!(xml.contains(
            "  <mime-type type=\"application/vnd.squashfs\">\n    \
             <glob pattern=\"*.sqfs\"/>\n    <glob pattern=\"*.squashfs\"/>\n  </mime-type>\n"
        ));
        assert!(xml.contains(
            "  <mime-type type=\"application/x-cba\">\n    \
             <comment>Comic book archive (ACE container)</comment>\n    \
             <sub-class-of type=\"application/x-ace\"/>\n"
        ));
    }

    #[test]
    fn the_overlay_ships_the_cli_the_mime_package_and_the_notices() {
        let root = crate::codegen::workspace_root();
        let dir = tempfile::tempdir().unwrap();
        let cli = dir.path().join("beezip");
        let associations = associations().unwrap();
        let staged = stage(&root, dir.path(), cli.clone(), &associations).unwrap();
        let count = associations.len();
        let config = config(&root, &staged, associations, "1.2.3", &|_| None).unwrap();
        assert_eq!(config["productName"], "beezip");
        assert_eq!(config["version"], "1.2.3");
        assert_eq!(super::super::null_at(&config, ""), None);
        let linux = &config["bundle"]["linux"];
        for kind in ["deb", "rpm", "appimage"] {
            let files = &linux[kind]["files"];
            assert_eq!(files["/usr/bin/beezip"], slashes(&cli), "{kind}");
            assert_eq!(
                files["/usr/share/mime/packages/beezip.xml"],
                slashes(&dir.path().join("beezip.xml"))
            );
            assert_eq!(
                files["/usr/share/doc/beezip/THIRD_PARTY_NOTICES.md"],
                slashes(&dir.path().join(NOTICES))
            );
        }
        assert_eq!(
            std::fs::read(dir.path().join(NOTICES)).unwrap(),
            std::fs::read(root.join(NOTICES)).unwrap()
        );
        #[cfg(unix)]
        for f in [NOTICES, "beezip.xml", "beezip.desktop"] {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(f))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o644, "{f}");
        }
        for kind in ["deb", "rpm"] {
            assert_eq!(
                linux[kind]["desktopTemplate"],
                slashes(&dir.path().join("beezip.desktop"))
            );
        }
        let postun = linux["rpm"]["postRemoveScript"].as_str().unwrap();
        assert!(
            std::fs::read_to_string(postun)
                .unwrap()
                .contains("rmdir /usr/share/doc/beezip")
        );
        assert_eq!(linux["deb"]["postRemoveScript"], Value::Null);
        let desktop = std::fs::read_to_string(dir.path().join("beezip.desktop")).unwrap();
        assert!(!desktop.contains(MIME_TYPES));
        assert!(
            desktop.contains("{{exec}}"),
            "Tauri fills in the executable"
        );
        let list = config["bundle"]["fileAssociations"].as_array().unwrap();
        assert_eq!(list.len(), count);
        assert!(list.iter().all(|a| a["mimeType"].is_string()));
        assert_eq!(
            bundles(Path::new("b"), "1.2.3")[2].1,
            Path::new("b").join("appimage/beezip_1.2.3_amd64.AppImage")
        );
    }

    /// The table against the shared-mime-info on this machine, where there is one (the Linux CI
    /// job and the bundle builds): each glob BeeZip relies on is there, on the type MIME names
    /// (or its older name, [`OLDER_NAMES`]), and each one BeeZip adds isn't, nor is a type it
    /// defines. Checked against 2.4 (Ubuntu 24.04), 2.2 (Debian 12) and 2.1 (Ubuntu 22.04).
    #[test]
    fn the_mime_table_matches_shared_mime_info() {
        let path = Path::new("/usr/share/mime/packages/freedesktop.org.xml");
        let Ok(xml) = std::fs::read_to_string(path) else {
            eprintln!("no {}: not checked", path.display());
            return;
        };
        let db = Database::parse(&xml);
        for (ext, mime) in MIME {
            let found = db.types_for(ext);
            if GLOBS.contains(ext) {
                assert!(
                    found.is_empty(),
                    "shared-mime-info has *.{ext} now: {found:?}"
                );
            } else {
                assert!(
                    found == [*mime] || older_name(mime).is_some_and(|old| found == [old]),
                    "*.{ext} is {found:?} here, not {mime}"
                );
            }
        }
        for (mime, _, _) in NEW_TYPES {
            assert!(!db.has_type(mime), "shared-mime-info has {mime} now");
        }
        for mime in MIME.iter().map(|(_, m)| m).chain(MORE_TYPES) {
            assert!(
                NEW_TYPES.iter().any(|(t, ..)| t == mime)
                    || db.has_type(mime)
                    || older_name(mime).is_some_and(|old| db.has_type(old)),
                "shared-mime-info has no {mime}"
            );
        }
    }

    /// Just enough of freedesktop.org.xml: each type and its globs.
    struct Database<'a> {
        types: Vec<(&'a str, Vec<&'a str>)>,
    }

    impl<'a> Database<'a> {
        fn parse(xml: &'a str) -> Self {
            let mut types = Vec::new();
            for block in xml.split("<mime-type type=\"").skip(1) {
                let name = &block[..block.find('"').unwrap()];
                let body = &block[..block.find("</mime-type>").unwrap_or(block.len())];
                let globs = body
                    .split("<glob pattern=\"")
                    .skip(1)
                    .map(|g| &g[..g.find('"').unwrap()])
                    .collect();
                types.push((name, globs));
            }
            Self { types }
        }

        fn has_type(&self, mime: &str) -> bool {
            self.types.iter().any(|(t, _)| *t == mime)
        }

        /// The types with a glob `*.<ext>`, matched without regard to case as shared-mime-info
        /// does unless a glob says otherwise (none of these do).
        fn types_for(&self, ext: &str) -> Vec<&'a str> {
            let want = format!("*.{ext}");
            self.types
                .iter()
                .filter(|(_, globs)| globs.iter().any(|g| g.eq_ignore_ascii_case(&want)))
                .map(|(t, _)| *t)
                .collect()
        }
    }
}
