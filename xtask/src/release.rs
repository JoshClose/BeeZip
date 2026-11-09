//! Releases (docs/M6.md §9.5):
//! - `cargo xtask release --version V` writes V everywhere the version is kept, on a clean tree,
//!   before the tag: the workspace's `Cargo.toml`, the workspace crates' entries in both lock
//!   files (the fuzz workspace's too), `apps/desktop/package.json`, and `tauri.conf.json` when it
//!   carries one (today it doesn't: Tauri takes the desktop crate's, which is the workspace's).
//!   It prints the commands to commit and tag; it never commits or tags itself.
//! - `cargo xtask release --check-tag TAG`: release.yml's check that a tag is `v` and the
//!   workspace's version.
//! - [`latest_json`]: the updater's manifest, which `xtask dist` writes beside a signed installer.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use serde_json::{Value, json};
use toml_edit::{DocumentMut, Item};

use crate::codegen::workspace_root;

/// The GitHub repository releases are made in.
pub const REPO: &str = "JoshClose/BeeZip";

/// `https://github.com/JoshClose/BeeZip`.
pub fn repo_url() -> String {
    format!("https://github.com/{REPO}")
}

/// Where a release's file is downloaded from once the release is published.
pub fn download_url(version: &str, file: &str) -> String {
    format!("{}/releases/download/v{version}/{file}", repo_url())
}

/// A release's page.
pub fn release_url(version: &str) -> String {
    format!("{}/releases/tag/v{version}", repo_url())
}

const CARGO_TOML: &str = "Cargo.toml";
const LOCKS: &[&str] = &["Cargo.lock", "fuzz/Cargo.lock"];
const PACKAGE_JSON: &str = "apps/desktop/package.json";
const TAURI_CONF: &str = "apps/desktop/src-tauri/tauri.conf.json";

pub fn run(version: &str) -> anyhow::Result<()> {
    let root = workspace_root();
    let out = Command::new("git")
        .current_dir(&root)
        .args(["status", "--porcelain"])
        .output()
        .context("starting git")?;
    if !out.status.success() {
        bail!(
            "git status failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let changes = String::from_utf8_lossy(&out.stdout);
    if !changes.trim().is_empty() {
        bail!("the tree isn't clean; commit or put away these first:\n{changes}");
    }
    let current = workspace_version(&root)?;
    check_newer(&current, version)?;
    let edits = bump(&root, &current, version)?;
    for (path, text) in &edits {
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
    }
    // The lock must still agree with the manifests, or a `--locked` build would refuse it.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let metadata = Command::new(cargo)
        .current_dir(&root)
        .args(["metadata", "--locked", "--offline", "--format-version", "1"])
        .output()
        .context("starting cargo metadata")?;
    if !metadata.status.success() {
        bail!(
            "Cargo.lock doesn't agree with the manifests after the bump (`git checkout -- .` \
             undoes it):\n{}",
            String::from_utf8_lossy(&metadata.stderr)
        );
    }
    println!(
        "\nBeeZip is now {version} (was {current}). Nothing is committed or tagged; next:\n\
         \n  git commit -am \"Release {version}\"\
         \n  (push it, through a pull request if master needs one, and merge it)\
         \n  git tag -a v{version} -m \"BeeZip {version}\" <the commit on master>\
         \n  git push origin v{version}\n\
         \nThe tag starts .github/workflows/release.yml, which builds the installer and makes a \
         draft release, v{version}. Publishing it is yours."
    );
    Ok(())
}

/// release.yml's check: `tag` is `v` and the workspace's version.
pub fn check_tag(tag: &str) -> anyhow::Result<()> {
    let version = workspace_version(&workspace_root())?;
    if tag != format!("v{version}") {
        bail!(
            "the tag is {tag}, but the workspace's version is {version}: tag v{version}, or bump \
             the version with `cargo xtask release --version` first"
        );
    }
    println!("{tag} is the workspace's version");
    Ok(())
}

/// `[workspace.package] version` in the root `Cargo.toml`.
pub fn workspace_version(root: &Path) -> anyhow::Result<String> {
    let doc = read_toml(&root.join(CARGO_TOML))?;
    doc["workspace"]["package"]["version"]
        .as_str()
        .map(str::to_owned)
        .context("Cargo.toml has no [workspace.package] version")
}

/// Fails unless `version` is a version (semver), without the tag's `v`.
pub fn check_version(version: &str) -> anyhow::Result<()> {
    Version::parse(version).map(|_| ())
}

/// Fails unless `new` is a version (semver) above `current`, and one Windows can carry: the
/// package and the installer's version info take four numbers of at most 65535.
pub fn check_newer(current: &str, new: &str) -> anyhow::Result<()> {
    let parsed = Version::parse(new)?;
    let old = Version::parse(current)?;
    if parsed <= old {
        bail!("{new} isn't above the current version, {current}");
    }
    crate::sparse::package_version(new)?;
    Ok(())
}

/// The new text of every file that carries the version, `old` → `new`.
pub fn bump(root: &Path, old: &str, new: &str) -> anyhow::Result<Vec<(PathBuf, String)>> {
    let mut edits = Vec::new();

    let path = root.join(CARGO_TOML);
    let mut doc = read_toml(&path)?;
    let members = members(root, &doc)?;
    let version = &mut doc["workspace"]["package"]["version"];
    if version.as_str() != Some(old) {
        bail!(
            "{} has no [workspace.package] version {old}",
            path.display()
        );
    }
    set_str(version, new);
    edits.push((path, doc.to_string()));

    for (i, lock) in LOCKS.iter().enumerate() {
        let path = root.join(lock);
        if !path.is_file() {
            continue;
        }
        let mut doc = read_toml(&path)?;
        let mut changed = BTreeSet::new();
        if let Some(packages) = doc
            .get_mut("package")
            .and_then(Item::as_array_of_tables_mut)
        {
            for p in packages.iter_mut() {
                // A path dependency has no `source`; only the workspace's own crates change.
                let name = p.get("name").and_then(Item::as_str).map(str::to_owned);
                let Some(name) = name.filter(|n| members.contains(n)) else {
                    continue;
                };
                if p.contains_key("source") || p.get("version").and_then(Item::as_str) != Some(old)
                {
                    continue;
                }
                if let Some(v) = p.get_mut("version") {
                    set_str(v, new);
                    changed.insert(name);
                }
            }
        }
        // The workspace's own lock lists every member; the fuzz workspace's only those it uses.
        if i == 0 && changed != members {
            let missing: Vec<&String> = members.difference(&changed).collect();
            bail!("{} has no {old} entry for {missing:?}", path.display());
        }
        if !changed.is_empty() {
            edits.push((path, doc.to_string()));
        }
    }

    let path = root.join(PACKAGE_JSON);
    let text = read(&path)?;
    edits.push((
        path.clone(),
        json_version(&text, old, new)?
            .with_context(|| format!("{} has no version {old}", path.display()))?,
    ));

    let path = root.join(TAURI_CONF);
    let text = read(&path)?;
    match json_version(&text, old, new)? {
        Some(text) => edits.push((path, text)),
        // A version that isn't this one (Tauri also takes a path to a package.json) stays.
        None if serde_json::from_str::<Value>(&text)?
            .get("version")
            .is_some() =>
        {
            println!("{} keeps its own version setting", path.display())
        }
        None => {}
    }
    Ok(edits)
}

/// The workspace's crates that take its version (`version.workspace = true`), by name.
fn members(root: &Path, workspace: &DocumentMut) -> anyhow::Result<BTreeSet<String>> {
    let list = workspace["workspace"]["members"]
        .as_array()
        .context("Cargo.toml has no [workspace] members")?;
    let mut out = BTreeSet::new();
    for dir in list.iter().filter_map(|m| m.as_str()) {
        let doc = read_toml(&root.join(dir).join(CARGO_TOML))?;
        let package = &doc["package"];
        let inherits = package["version"]
            .as_table_like()
            .and_then(|t| t.get("workspace"))
            .and_then(Item::as_bool)
            == Some(true);
        if let (true, Some(name)) = (inherits, package["name"].as_str()) {
            out.insert(name.to_owned());
        }
    }
    if out.is_empty() {
        bail!("no workspace crate takes the workspace's version");
    }
    Ok(out)
}

/// The JSON text with its top-level `"version": "old"` made `new`, the rest as it was; None when
/// it has no such version.
fn json_version(text: &str, old: &str, new: &str) -> anyhow::Result<Option<String>> {
    let top = |t: &str| -> anyhow::Result<Option<String>> {
        Ok(serde_json::from_str::<Value>(t)?
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned))
    };
    if top(text)?.as_deref() != Some(old) {
        return Ok(None);
    }
    // The first `"version": "old"`, which in these files is the top-level one; checked below.
    let mut from = 0;
    while let Some(at) = text[from..].find("\"version\"").map(|i| from + i) {
        let rest = text[at + "\"version\"".len()..].trim_start();
        if let Some(value) = rest.strip_prefix(':').map(str::trim_start)
            && value.starts_with(&format!("\"{old}\""))
        {
            let start = text.len() - value.len() + 1;
            let out = format!("{}{new}{}", &text[..start], &text[start + old.len()..]);
            if top(&out)?.as_deref() != Some(new) {
                bail!("the first \"version\" isn't the top-level one");
            }
            return Ok(Some(out));
        }
        from = at + 1;
    }
    bail!("couldn't find \"version\": \"{old}\" in the text")
}

/// Replaces a string value, keeping the spaces and comments around it.
fn set_str(item: &mut Item, new: &str) {
    let decor = item.as_value().map(|v| v.decor().clone());
    *item = toml_edit::value(new);
    if let (Some(decor), Some(v)) = (decor, item.as_value_mut()) {
        *v.decor_mut() = decor;
    }
}

fn read(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

fn read_toml(path: &Path) -> anyhow::Result<DocumentMut> {
    read(path)?
        .parse()
        .with_context(|| format!("parsing {}", path.display()))
}

/// A semantic version (semver.org): what Cargo, npm and Tauri's updater take.
#[derive(Debug, PartialEq, Eq)]
struct Version {
    core: [u64; 3],
    pre: Vec<String>,
}

impl Version {
    fn parse(text: &str) -> anyhow::Result<Version> {
        let bad = || anyhow::anyhow!("{text} isn't a version (semver: 1.2.3, 1.2.3-beta.1)");
        if text.starts_with('v') {
            bail!("{text}: give the version without the `v`, which only the tag has");
        }
        let (rest, build) = match text.split_once('+') {
            Some((r, b)) => (r, Some(b)),
            None => (text, None),
        };
        let (core, pre) = match rest.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (rest, None),
        };
        let number = |p: &str| -> Option<u64> {
            let leading_zero = p.len() > 1 && p.starts_with('0');
            (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && !leading_zero)
                .then(|| p.parse().ok())
                .flatten()
        };
        let parts: Vec<u64> = core
            .split('.')
            .map(number)
            .collect::<Option<_>>()
            .ok_or_else(bad)?;
        let core: [u64; 3] = parts.try_into().map_err(|_| bad())?;
        let ident =
            |i: &&str| !i.is_empty() && i.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        let pre: Vec<String> = match pre {
            Some(p) => {
                let ids: Vec<&str> = p.split('.').collect();
                let numeric_with_zero = |i: &&str| {
                    i.len() > 1 && i.starts_with('0') && i.bytes().all(|b| b.is_ascii_digit())
                };
                if !ids.iter().all(ident) || ids.iter().any(numeric_with_zero) {
                    return Err(bad());
                }
                ids.into_iter().map(str::to_owned).collect()
            }
            None => Vec::new(),
        };
        if build.is_some_and(|b| !b.split('.').all(|i| ident(&i))) {
            return Err(bad());
        }
        Ok(Version { core, pre })
    }
}

impl Ord for Version {
    /// semver's precedence: the numbers, then a pre-release below its release, then the
    /// pre-release's identifiers (numbers below words); build metadata doesn't count.
    fn cmp(&self, other: &Self) -> Ordering {
        self.core
            .cmp(&other.core)
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let order = match (a.parse::<u64>(), b.parse::<u64>()) {
                            (Ok(x), Ok(y)) => x.cmp(&y),
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            (Err(_), Err(_)) => a.cmp(b),
                        };
                        if order != Ordering::Equal {
                            return order;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A bundle in `latest.json`: its key (`windows-x86_64-nsis`, `linux-x86_64-deb`…), its file's
/// name in the release, and its `.sig` file's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub key: String,
    pub file: String,
    pub signature: String,
}

/// The updater's `latest.json` for this version's bundles on one platform (docs/M6.md §9.4), as
/// the GitHub release serves it. release.yml merges every platform's into one.
pub fn latest_json(version: &str, platforms: &[Platform], pub_date: &str) -> Value {
    let platforms: serde_json::Map<String, Value> = platforms
        .iter()
        .map(|p| {
            (
                p.key.clone(),
                json!({
                    "signature": p.signature.trim(),
                    "url": download_url(version, &p.file),
                }),
            )
        })
        .collect();
    json!({
        "version": version,
        "notes": format!("See {}", release_url(version)),
        "pub_date": pub_date,
        "platforms": platforms,
    })
}

/// A time as RFC 3339 in UTC, to the second: `2026-11-07T13:48:11Z`.
pub fn rfc3339(time: SystemTime) -> String {
    let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // Days since 1970-01-01 to a date, after Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::time::Duration;

    use super::*;

    #[test]
    fn versions_compare_as_semver_says() {
        let v = |t: &str| Version::parse(t).unwrap();
        let ordered = [
            "0.1.0",
            "0.1.1",
            "0.2.0",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.10.0",
            "10.0.0",
        ];
        for pair in ordered.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        assert_eq!(v("1.0.0+build.5"), v("1.0.0"));
        for bad in [
            "1",
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.0.0-",
            "1.0.0-01",
            "1.0.0+",
            "v1.0.0",
            "1.0.x",
            "1.0.0-a..b",
            " 1.0.0",
        ] {
            assert!(Version::parse(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn a_release_must_go_up() {
        assert!(check_newer("0.1.0", "0.1.1").is_ok());
        assert!(check_newer("0.1.0", "1.0.0-beta.1").is_ok());
        assert!(check_newer("0.1.0", "0.1.0").is_err());
        assert!(check_newer("1.0.0", "1.0.0-rc.1").is_err());
        assert!(check_newer("0.1.0", "0.0.9").is_err());
        // The package's four numbers stop at 65535.
        assert!(check_newer("0.1.0", "0.70000.0").is_err());
    }

    /// A workspace like this one, in a temporary folder.
    fn workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = workspace_root();
        let w = |rel: &str, text: &str| {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        // The real files, so the test sees their layout as it is.
        for file in [
            CARGO_TOML,
            "Cargo.lock",
            "fuzz/Cargo.lock",
            PACKAGE_JSON,
            TAURI_CONF,
        ] {
            w(file, &std::fs::read_to_string(root.join(file)).unwrap());
        }
        let doc = read_toml(&root.join(CARGO_TOML)).unwrap();
        for m in doc["workspace"]["members"].as_array().unwrap() {
            let m = m.as_str().unwrap();
            let manifest = format!("{m}/Cargo.toml");
            w(
                &manifest,
                &std::fs::read_to_string(root.join(&manifest)).unwrap(),
            );
        }
        dir
    }

    #[test]
    fn the_bump_writes_every_copy_of_the_version_and_nothing_else() {
        let dir = workspace();
        let root = dir.path();
        let old = workspace_version(root).unwrap();
        let edits = bump(root, &old, "7.8.9-rc.1").unwrap();
        let files: Vec<String> = edits
            .iter()
            .map(|(p, _)| {
                p.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            files,
            [CARGO_TOML, "Cargo.lock", "fuzz/Cargo.lock", PACKAGE_JSON]
        );
        for (path, text) in &edits {
            let before = std::fs::read_to_string(path).unwrap();
            let changed: Vec<(&str, &str)> = before
                .lines()
                .zip(text.lines())
                .filter(|(a, b)| a != b)
                .collect();
            assert_eq!(before.lines().count(), text.lines().count(), "{path:?}");
            assert!(!changed.is_empty(), "{path:?}");
            for (a, b) in changed {
                assert_eq!(a.replace(&old, "7.8.9-rc.1"), b, "{path:?}");
                assert!(a.contains("version"), "{path:?}: {a}");
            }
            std::fs::write(path, text).unwrap();
        }
        assert_eq!(workspace_version(root).unwrap(), "7.8.9-rc.1");
        let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
        for name in ["beezip-core", "beezip-desktop", "xtask"] {
            assert!(
                lock.contains(&format!("name = \"{name}\"\nversion = \"7.8.9-rc.1\"\n")),
                "{name}"
            );
        }
        let fuzz = std::fs::read_to_string(root.join("fuzz/Cargo.lock")).unwrap();
        assert!(fuzz.contains("name = \"beezip-core\"\nversion = \"7.8.9-rc.1\"\n"));
        assert!(fuzz.contains("name = \"beezip-fuzz\"\nversion = \"0.0.0\"\n"));
        let package: Value =
            serde_json::from_str(&std::fs::read_to_string(root.join(PACKAGE_JSON)).unwrap())
                .unwrap();
        assert_eq!(package["version"], "7.8.9-rc.1");
    }

    #[test]
    fn a_version_in_tauri_conf_is_bumped_too() {
        let text = "{\n  \"productName\": \"BeeZip\",\n  \"version\": \"0.1.0\",\n  \"plugins\": { \"x\": { \"version\": \"0.1.0\" } }\n}\n";
        let out = json_version(text, "0.1.0", "0.2.0").unwrap().unwrap();
        assert_eq!(out, text.replacen("\"0.1.0\"", "\"0.2.0\"", 1));
        // Nested first: the top-level one must be the one changed, or nothing.
        let nested = "{ \"plugins\": { \"version\": \"0.1.0\" }, \"version\": \"0.1.0\" }";
        assert!(json_version(nested, "0.1.0", "0.2.0").is_err());
        assert_eq!(
            json_version("{ \"version\": \"../package.json\" }", "0.1.0", "0.2.0").unwrap(),
            None
        );
        assert_eq!(json_version("{}", "0.1.0", "0.2.0").unwrap(), None);
    }

    #[test]
    fn the_update_manifest_points_at_the_release() {
        let latest = latest_json(
            "0.2.0",
            &[Platform {
                key: "windows-x86_64-nsis".into(),
                file: "BeeZip_0.2.0_x64-setup.exe".into(),
                signature: "c2lnbmF0dXJl\n".into(),
            }],
            "2026-11-07T13:48:11Z",
        );
        assert_eq!(
            latest,
            json!({
                "version": "0.2.0",
                "notes": "See https://github.com/JoshClose/BeeZip/releases/tag/v0.2.0",
                "pub_date": "2026-11-07T13:48:11Z",
                "platforms": {
                    "windows-x86_64-nsis": {
                        "signature": "c2lnbmF0dXJl",
                        "url": "https://github.com/JoshClose/BeeZip/releases/download/v0.2.0/BeeZip_0.2.0_x64-setup.exe",
                    }
                }
            })
        );
    }

    #[test]
    fn times_are_rfc3339_in_utc() {
        let at = |s: u64| rfc3339(UNIX_EPOCH + Duration::from_secs(s));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_794_059_291), "2026-11-07T13:48:11Z");
        assert_eq!(at(4_107_542_399), "2100-02-28T23:59:59Z");
    }
}
