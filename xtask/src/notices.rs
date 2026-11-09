//! `cargo xtask notices [--check]`: THIRD_PARTY_NOTICES.md, generated (docs/M6.md §9.1).
//!
//! The file is, in order:
//! - the hand-written parts in `packaging/notices/`: `header.md` (BeeZip's license, UnRAR, the
//!   MPL statement) and `code-taken-in.md` (code BeeZip took into its own source, UnRAR's
//!   license in full, the vendored hadris-iso);
//! - the Rust crates of the three shipped programs, from cargo-about 0.9.3 with `about.toml`, run
//!   offline once for each of beezip-desktop, beezip-cli and beezip-shell and merged (it takes
//!   one package or the whole workspace, which would add xtask);
//! - the npm packages whose code is in the interface's bundle, from the list the Vite plugin in
//!   `apps/desktop/vite.config.ts` writes during `pnpm build`.
//!
//! Licenses are grouped by id and text (whitespace aside), packages are named by name@version, and
//! everything is sorted, so the file depends only on the lockfiles, about.toml and the hand-written
//! parts: no paths, no dates. A crate whose license text cargo-about doesn't find fails the task
//! (its fallback, the license's canonical text, has no copyright line) unless
//! `packaging/notices/notices.toml` lists it; that file also holds the texts of the npm packages
//! that ship none.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::Path,
    process::Command,
};

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;

use crate::codegen::workspace_root;

/// Relative to the workspace root.
pub const OUTPUT: &str = "THIRD_PARTY_NOTICES.md";
/// Written by the Vite plugin; cargo-about's output goes beside it.
const NPM_LIST: &str = "target/notices/npm-packages.json";
const WORK_DIR: &str = "target/notices";
const HAND_WRITTEN: &str = "packaging/notices";
const SETTINGS: &str = "packaging/notices/notices.toml";
const CARGO_ABOUT: &str = "cargo-about 0.9.3";
const INSTALL: &str = "cargo install --locked cargo-about --version 0.9.3 --features cli";
const REGENERATE: &str = "run `cargo xtask notices` (after `pnpm --dir apps/desktop build`)";
/// The shipped programs' crates (BeeZip.exe, bin\beezip.exe, the Explorer menu's DLL).
const SHIPPED: [(&str, &str); 3] = [
    ("beezip-desktop", "apps/desktop/src-tauri"),
    ("beezip-cli", "crates/beezip-cli"),
    ("beezip-shell", "crates/beezip-shell"),
];
/// about.toml's `targets`.
const TARGET: &str = "x86_64-pc-windows-msvc";
/// The licenses an npm package may be under, in the order one is taken from a choice, with their
/// SPDX names. The Vite plugin fails the build on any other.
const NPM_LICENSES: [(&str, &str); 6] = [
    ("MIT", "MIT License"),
    ("ISC", "ISC License"),
    ("Apache-2.0", "Apache License 2.0"),
    ("0BSD", "BSD Zero Clause License"),
    ("BSD-2-Clause", "BSD 2-Clause \"Simplified\" License"),
    (
        "BSD-3-Clause",
        "BSD 3-Clause \"New\" or \"Revised\" License",
    ),
];

/// cargo-about's `--format json` output, the parts used here.
#[derive(Debug, Deserialize)]
struct About {
    licenses: Vec<AboutLicense>,
    crates: Vec<AboutCrate>,
}

#[derive(Debug, Deserialize)]
struct AboutLicense {
    id: String,
    name: String,
    text: String,
    /// None when cargo-about found no text in the crate and took the license's canonical one,
    /// which has no copyright line.
    source_path: Option<String>,
    used_by: Vec<UsedBy>,
}

#[derive(Debug, Deserialize)]
struct UsedBy {
    #[serde(rename = "crate")]
    krate: Package,
}

#[derive(Debug, Deserialize)]
struct AboutCrate {
    package: Package,
    /// The license expression, a clarification's if about.toml gives one.
    license: String,
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    version: String,
}

impl Package {
    fn key(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// An entry of the Vite plugin's list.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NpmPackage {
    name: String,
    version: String,
    license: String,
    /// The package's license files by name (LICENSE, LICENSE-MIT…), with their text.
    license_files: BTreeMap<String, String>,
}

/// `packaging/notices/notices.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Settings {
    /// Crates, by name, allowed the canonical text of their license.
    no_license_file: BTreeSet<String>,
    /// Texts for npm packages that ship none, by package name.
    #[serde(default)]
    npm: BTreeMap<String, NpmText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NpmText {
    license: String,
    text: String,
}

/// A license text and the packages (name@version) under it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Text {
    id: String,
    name: String,
    text: String,
    users: BTreeSet<String>,
}

/// One section of the file: the Rust crates or the npm packages, and their license texts.
#[derive(Debug, Default)]
struct Section {
    /// name@version → its license expression.
    packages: BTreeMap<String, String>,
    /// (id, the text with its whitespace collapsed) → the text.
    texts: BTreeMap<(String, String), Text>,
}

impl Section {
    fn add(&mut self, id: &str, name: &str, text: &str, user: String) {
        let text = clean(text);
        let entry = self
            .texts
            .entry((id.to_owned(), collapse(&text)))
            .or_insert_with(|| Text {
                id: id.to_owned(),
                name: name.to_owned(),
                text: text.clone(),
                users: BTreeSet::new(),
            });
        // Texts that differ in whitespace only: the same one whichever run came first.
        if text < entry.text {
            entry.text = text;
        }
        entry.users.insert(user);
    }

    /// Each license id with the number of packages under it, most first.
    fn counts(&self) -> Vec<(&str, usize)> {
        let mut users: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for t in self.texts.values() {
            users
                .entry(&t.id)
                .or_default()
                .extend(t.users.iter().map(String::as_str));
        }
        let mut counts: Vec<_> = users.into_iter().map(|(id, u)| (id, u.len())).collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        counts
    }

    /// The texts in print order: by license as in `counts`, then by their first package.
    fn ordered(&self) -> Vec<&Text> {
        let rank: BTreeMap<&str, usize> = self
            .counts()
            .into_iter()
            .enumerate()
            .map(|(i, (id, _))| (id, i))
            .collect();
        let mut texts: Vec<&Text> = self.texts.values().collect();
        texts.sort_by(|a, b| {
            rank[a.id.as_str()]
                .cmp(&rank[b.id.as_str()])
                .then_with(|| a.users.first().cmp(&b.users.first()))
                .then_with(|| a.text.cmp(&b.text))
        });
        texts
    }
}

pub fn run(check: bool) -> anyhow::Result<()> {
    let root = workspace_root();
    let (generated, summary) = generate(&root)?;
    let path = root.join(OUTPUT);
    let current = std::fs::read_to_string(&path)
        .ok()
        .map(|t| t.replace("\r\n", "\n"));
    if current.as_deref() == Some(generated.as_str()) {
        println!("{OUTPUT} is up to date: {summary}");
    } else if check {
        bail!("{OUTPUT} is out of date; {REGENERATE}");
    } else {
        std::fs::write(&path, &generated)
            .with_context(|| format!("could not write {}", path.display()))?;
        println!("wrote {OUTPUT}: {summary}");
    }
    Ok(())
}

/// The file's contents, and a one-line summary of them.
fn generate(root: &Path) -> anyhow::Result<(String, String)> {
    let npm_list = root.join(NPM_LIST);
    let npm: Vec<NpmPackage> = match std::fs::read(&npm_list) {
        Ok(json) => {
            serde_json::from_slice(&json).with_context(|| format!("could not read {NPM_LIST}"))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "{NPM_LIST} is missing: run `pnpm --dir apps/desktop build` first. Its Vite plugin \
             lists the npm packages in the bundle"
        ),
        Err(e) => return Err(e).with_context(|| format!("could not read {NPM_LIST}")),
    };
    let settings: Settings = toml::from_str(&read(root, SETTINGS)?)
        .with_context(|| format!("could not read {SETTINGS}"))?;
    let hand_written = [
        read(root, &format!("{HAND_WRITTEN}/header.md"))?,
        read(root, &format!("{HAND_WRITTEN}/code-taken-in.md"))?,
    ];

    check_cargo_about(root)?;
    std::fs::create_dir_all(root.join(WORK_DIR))?;
    let abouts = std::thread::scope(|s| {
        let runs: Vec<_> = SHIPPED
            .iter()
            .map(|&(name, dir)| s.spawn(move || cargo_about(root, name, dir)))
            .collect();
        runs.into_iter()
            .map(|run| {
                run.join()
                    .map_err(|_| anyhow!("a cargo-about run panicked"))?
            })
            .collect::<anyhow::Result<Vec<About>>>()
    })?;

    let (rust, canonical) = merge_rust(&abouts);
    check_rust(&rust, &canonical, &settings.no_license_file)?;
    let npm = merge_npm(&npm, &settings.npm)?;
    let text = render(&hand_written, &rust, &npm);
    let summary = format!(
        "{} crates in {} texts, {} npm packages in {} texts, {} bytes",
        rust.packages.len(),
        rust.texts.len(),
        npm.packages.len(),
        npm.texts.len(),
        text.len()
    );
    Ok((text, summary))
}

/// A file of the repository, with LF line ends.
fn read(root: &Path, path: &str) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(root.join(path))
        .with_context(|| format!("could not read {path}"))?;
    Ok(text.replace("\r\n", "\n"))
}

fn cargo() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// The output depends on cargo-about's version, so only the pinned one is used.
fn check_cargo_about(root: &Path) -> anyhow::Result<()> {
    let out = Command::new(cargo())
        .args(["about", "--version"])
        .current_dir(root)
        .output();
    let version = match out {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        _ => bail!("cargo-about isn't installed; install it with `{INSTALL}`"),
    };
    if version != CARGO_ABOUT {
        bail!(
            "the notices are generated with {CARGO_ABOUT}, not {version}; install it with `{INSTALL}`"
        );
    }
    Ok(())
}

/// cargo-about's licenses for one shipped crate. It writes a file rather than to stdout, which
/// it refuses when PowerShell is a parent process.
fn cargo_about(root: &Path, name: &str, dir: &str) -> anyhow::Result<About> {
    let out = root.join(WORK_DIR).join(format!("about-{name}.json"));
    let _ = std::fs::remove_file(&out);
    let output = Command::new(cargo())
        .current_dir(root)
        .args(["about", "--color", "never", "generate", "--format", "json"])
        .args(["--offline", "--locked", "--fail", "--config"])
        .arg(root.join("about.toml"))
        .arg("--manifest-path")
        .arg(root.join(dir).join("Cargo.toml"))
        .arg("--output-file")
        .arg(&out)
        .output()
        .context("could not run cargo-about")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        bail!("cargo-about failed for {name}:\n{stderr}");
    }
    // Its own warnings (a clarification that didn't apply…), without their timestamps. The
    // "config found for a crate not present in the graph" diagnostics are left out: about.toml
    // serves all three crates.
    for line in stderr.lines().map(plain) {
        if let Some(at) = line.find("[WARN]").or_else(|| line.find("[ERROR]")) {
            eprintln!("cargo-about ({name}): {}", &line[at..]);
        }
    }
    let json = std::fs::read(&out).with_context(|| format!("could not read {}", out.display()))?;
    serde_json::from_slice(&json).with_context(|| format!("cargo-about's output for {name}"))
}

/// A line without its ANSI escapes: cargo-about colours its log's levels even with
/// `--color never`, which only reaches its diagnostics.
fn plain(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ESC [ parameters, up to the final byte (@ to ~).
            for c in chars.by_ref() {
                if c != '[' && ('@'..='~').contains(&c) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Merges cargo-about's runs. Returns the crates and their texts, and the crates (by name) that
/// got a license's canonical text, with name@version and the license for each.
fn merge_rust(abouts: &[About]) -> (Section, BTreeMap<String, BTreeSet<String>>) {
    let mut rust = Section::default();
    let mut canonical: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for about in abouts {
        for c in &about.crates {
            rust.packages.insert(c.package.key(), c.license.clone());
        }
        for l in &about.licenses {
            for u in &l.used_by {
                rust.add(&l.id, &l.name, &l.text, u.krate.key());
                if l.source_path.is_none() {
                    canonical
                        .entry(u.krate.name.clone())
                        .or_default()
                        .insert(format!("{} ({})", u.krate.key(), l.id));
                }
            }
        }
    }
    (rust, canonical)
}

/// Fails on a crate given a canonical text that `allowed` doesn't name, on a crate `allowed` names
/// that has a text of its own, and on a `LicenseRef-` without its text (cargo-about drops them,
/// see about.toml).
fn check_rust(
    rust: &Section,
    canonical: &BTreeMap<String, BTreeSet<String>>,
    allowed: &BTreeSet<String>,
) -> anyhow::Result<()> {
    let unexpected: Vec<&str> = canonical
        .iter()
        .filter(|(name, _)| !allowed.contains(*name))
        .flat_map(|(_, found)| found.iter().map(String::as_str))
        .collect();
    if !unexpected.is_empty() {
        bail!(
            "cargo-about found no license text in {}, so it took the license's canonical text, \
             without a copyright line. Name the crate's license file in about.toml (a clarification, \
             as for windows-rs), or, if no copy of it is in cargo's registry, list the crate under \
             no-license-file in {SETTINGS}",
            unexpected.join(", ")
        );
    }
    let stale: Vec<&str> = allowed
        .iter()
        .filter(|name| !canonical.contains_key(*name))
        .map(String::as_str)
        .collect();
    if !stale.is_empty() {
        bail!(
            "{SETTINGS} lists {} under no-license-file, but cargo-about found a text of its own, or \
             the crate isn't shipped: remove it there",
            stale.join(", ")
        );
    }
    for (krate, expression) in &rust.packages {
        for id in expression
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .filter(|t| t.starts_with("LicenseRef-"))
        {
            let found = rust
                .texts
                .values()
                .any(|t| t.id == id && t.users.contains(krate) && !t.text.is_empty());
            if !found {
                bail!(
                    "cargo-about gave {krate} no text for {id}; about.toml's workaround for its \
                     LicenseRef bug must have stopped working"
                );
            }
        }
    }
    Ok(())
}

/// The license BeeZip takes from an npm package's expression: the first of NPM_LICENSES that it
/// offers, as (id, name). None for anything else, `AND` included (no package has one today).
fn elect(expression: &str) -> Option<(&'static str, &'static str)> {
    let inner = expression
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')');
    if inner.contains(" AND ") || inner.contains(['(', ')']) {
        return None;
    }
    let offered: Vec<&str> = inner.split(" OR ").map(str::trim).collect();
    NPM_LICENSES
        .into_iter()
        .find(|(id, _)| offered.contains(id))
}

/// The package's text for `id`: its only license file, or among several the one named for `id`
/// (LICENSE-MIT…). None when it ships none.
fn npm_text<'a>(p: &'a NpmPackage, id: &str) -> anyhow::Result<Option<&'a str>> {
    let files: Vec<(&String, &String)> = p.license_files.iter().collect();
    match files.as_slice() {
        [] => Ok(None),
        [(_, text)] => Ok(Some(text.as_str())),
        _ => {
            let word = match id {
                "Apache-2.0" => "APACHE",
                "BSD-2-Clause" | "BSD-3-Clause" => "BSD",
                other => other,
            };
            let named: Vec<_> = files
                .iter()
                .filter(|(f, _)| f.to_ascii_uppercase().contains(word))
                .collect();
            match named.as_slice() {
                [(_, text)] => Ok(Some(text.as_str())),
                _ => bail!(
                    "{}@{} ships {}, and not one file named for {id}",
                    p.name,
                    p.version,
                    files
                        .iter()
                        .map(|(f, _)| f.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
    }
}

/// The npm packages and their texts, from the package's own files or from notices.toml.
fn merge_npm(
    packages: &[NpmPackage],
    given: &BTreeMap<String, NpmText>,
) -> anyhow::Result<Section> {
    let mut npm = Section::default();
    let mut used = BTreeSet::new();
    for p in packages {
        let key = format!("{}@{}", p.name, p.version);
        let (id, name) = elect(&p.license).with_context(|| {
            format!(
                "{key} is under {}: the notices take one of {}, or a choice among them",
                p.license,
                NPM_LICENSES.map(|(id, _)| id).join(", ")
            )
        })?;
        let text = match (npm_text(p, id)?, given.get(&p.name)) {
            (Some(_), Some(_)) => bail!(
                "{key} ships its license text: remove [npm.\"{}\"] from {SETTINGS}",
                p.name
            ),
            (Some(text), None) => text,
            (None, Some(g)) if g.license == id => {
                used.insert(p.name.as_str());
                g.text.as_str()
            }
            (None, Some(g)) => bail!(
                "{SETTINGS} gives {key} a {} text, but BeeZip takes the package under {id}",
                g.license
            ),
            (None, None) => bail!(
                "{key} ships no license file: add its {id} text to {SETTINGS} ([npm.\"{}\"])",
                p.name
            ),
        };
        npm.packages.insert(key.clone(), p.license.clone());
        npm.add(id, name, text, key);
    }
    let unused: Vec<&str> = given
        .keys()
        .map(String::as_str)
        .filter(|name| !used.contains(name))
        .collect();
    if !unused.is_empty() {
        bail!(
            "{SETTINGS} has license texts for npm packages that aren't in the bundle: {}",
            unused.join(", ")
        );
    }
    Ok(npm)
}

const CHOICE: &str = "Each text below names the packages it covers; where a package offers a \
                      choice of licenses, it is the license BeeZip takes.";

/// The whole file: the hand-written parts, then the Rust crates and the npm packages.
fn render(hand_written: &[String], rust: &Section, npm: &Section) -> String {
    let mut md = String::new();
    for part in hand_written {
        md.push_str(part.trim());
        md.push_str("\n\n");
    }
    md.push_str(&format!(
        "## Rust crates\n\nBeeZip's programs (`BeeZip.exe`, `beezip.exe` and the Explorer menu's \
         DLL) are built for {TARGET} from {} crates, under these licenses. {CHOICE}\n\n",
        rust.packages.len()
    ));
    section(&mut md, rust, "Crates");
    md.push_str(&format!(
        "## npm packages\n\nBeeZip's interface bundles code from {} npm packages, under these \
         licenses. {CHOICE}\n\n",
        npm.packages.len()
    ));
    section(&mut md, npm, "Packages");
    md.truncate(md.trim_end().len());
    md.push('\n');
    md
}

fn section(md: &mut String, s: &Section, noun: &str) {
    md.push_str(&format!("| License | {noun} |\n|---|---:|\n"));
    for (id, n) in s.counts() {
        md.push_str(&format!("| {id} | {n} |\n"));
    }
    md.push('\n');
    for t in s.ordered() {
        let users: Vec<String> = t.users.iter().map(|u| format!("`{u}`")).collect();
        md.push_str(&format!(
            "### {}\n\nUsed by {}.\n\n{}\n",
            t.name,
            users.join(", "),
            fenced(&t.text)
        ));
    }
}

/// A license text as printed: LF line ends, no byte-order mark, no trailing whitespace on a line,
/// no blank lines around it.
fn clean(text: &str) -> String {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    lines.join("\n").trim_matches('\n').to_owned()
}

/// The key two texts are the same by: their words.
fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A fenced block, its fence longer than any run of backticks in the text.
fn fenced(text: &str) -> String {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest.max(2) + 1);
    format!("{fence}text\n{text}\n{fence}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn about(value: serde_json::Value) -> About {
        serde_json::from_value(value).unwrap()
    }

    fn krate(name: &str, version: &str) -> serde_json::Value {
        json!({ "crate": { "name": name, "version": version, "authors": [] } })
    }

    fn licensed(name: &str, version: &str, license: &str) -> serde_json::Value {
        json!({ "package": { "name": name, "version": version }, "license": license })
    }

    /// Two runs that share crates and texts, as the desktop's and the CLI's do.
    fn two_runs() -> Vec<About> {
        vec![
            about(json!({
                "overview": [],
                "licenses": [
                    { "id": "MIT", "name": "MIT License", "text": "Copyright (c) A\r\n\r\nPermission  is granted.\r\n",
                      "source_path": "C:\\reg\\a-1.0.0\\LICENSE", "used_by": [krate("a", "1.0.0")] },
                    { "id": "MIT", "name": "MIT License", "text": "Copyright <year> <copyright holders>\n",
                      "source_path": null, "used_by": [krate("c", "0.1.0")] },
                    { "id": "LicenseRef-UnRAR", "name": "LicenseRef-UnRAR", "text": "UnRAR's terms",
                      "source_path": "vendor/unrar/license.txt", "used_by": [krate("unrar_sys", "0.5.8")] },
                ],
                "crates": [
                    licensed("a", "1.0.0", "MIT"),
                    licensed("c", "0.1.0", "MIT"),
                    licensed("unrar_sys", "0.5.8", "(MIT OR Apache-2.0) AND LicenseRef-UnRAR"),
                ],
            })),
            about(json!({
                "overview": [],
                "licenses": [
                    { "id": "MIT", "name": "MIT License", "text": "Copyright (c) A\n\nPermission is\ngranted.",
                      "source_path": "/reg/b-2.0.0/LICENSE-MIT", "used_by": [krate("b", "2.0.0"), krate("a", "1.0.0")] },
                    { "id": "Apache-2.0", "name": "Apache License 2.0", "text": "\u{feff}Apache terms   \n",
                      "source_path": "/reg/b-2.0.0/LICENSE-APACHE", "used_by": [krate("b", "2.0.0")] },
                ],
                "crates": [licensed("a", "1.0.0", "MIT"), licensed("b", "2.0.0", "MIT AND Apache-2.0")],
            })),
        ]
    }

    fn npm_package(name: &str, license: &str, files: &[(&str, &str)]) -> NpmPackage {
        NpmPackage {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            license: license.to_owned(),
            license_files: files
                .iter()
                .map(|(f, t)| ((*f).to_owned(), (*t).to_owned()))
                .collect(),
        }
    }

    fn given(entries: &[(&str, &str, &str)]) -> BTreeMap<String, NpmText> {
        entries
            .iter()
            .map(|(name, license, text)| {
                (
                    (*name).to_owned(),
                    NpmText {
                        license: (*license).to_owned(),
                        text: (*text).to_owned(),
                    },
                )
            })
            .collect()
    }

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn runs_merge_by_license_and_text() {
        let (rust, canonical) = merge_rust(&two_runs());
        assert_eq!(
            rust.packages.keys().collect::<Vec<_>>(),
            ["a@1.0.0", "b@2.0.0", "c@0.1.0", "unrar_sys@0.5.8"]
        );
        // a's text from both runs is one text despite its line breaks and CRLF; c's canonical
        // one is another.
        assert_eq!(rust.texts.len(), 4);
        let a = &rust.texts[&(
            "MIT".to_owned(),
            "Copyright (c) A Permission is granted.".to_owned(),
        )];
        assert_eq!(a.users, names(&["a@1.0.0", "b@2.0.0"]));
        assert_eq!(a.text, "Copyright (c) A\n\nPermission  is granted.");
        let apache = rust.texts.values().find(|t| t.id == "Apache-2.0").unwrap();
        assert_eq!(apache.text, "Apache terms", "no BOM, no trailing spaces");
        assert_eq!(
            rust.counts(),
            [("MIT", 3), ("Apache-2.0", 1), ("LicenseRef-UnRAR", 1)]
        );
        assert_eq!(
            canonical,
            BTreeMap::from([("c".to_owned(), names(&["c@0.1.0 (MIT)"]))])
        );
    }

    #[test]
    fn canonical_texts_need_listing() {
        let (rust, canonical) = merge_rust(&two_runs());
        check_rust(&rust, &canonical, &names(&["c"])).unwrap();

        let err = check_rust(&rust, &canonical, &names(&[]))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("c@0.1.0 (MIT)") && err.contains("no-license-file"),
            "{err}"
        );

        let err = check_rust(&rust, &canonical, &names(&["c", "a"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("lists a under no-license-file"), "{err}");
    }

    #[test]
    fn a_license_ref_without_its_text_fails() {
        let mut runs = two_runs();
        runs[0].licenses.retain(|l| l.id != "LicenseRef-UnRAR");
        let (rust, canonical) = merge_rust(&runs);
        let err = check_rust(&rust, &canonical, &names(&["c"]))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unrar_sys@0.5.8 no text for LicenseRef-UnRAR"),
            "{err}"
        );
    }

    #[test]
    fn npm_licenses_are_taken_in_order() {
        assert_eq!(elect("MIT"), Some(("MIT", "MIT License")));
        assert_eq!(elect("(Apache-2.0 OR MIT)").map(|e| e.0), Some("MIT"));
        assert_eq!(elect("Apache-2.0 OR ISC").map(|e| e.0), Some("ISC"));
        assert_eq!(elect("0BSD").map(|e| e.0), Some("0BSD"));
        assert_eq!(elect("GPL-3.0-only"), None);
        assert_eq!(elect("MIT AND ISC"), None, "not handled");
        assert_eq!(elect("(MIT OR GPL-2.0) AND ISC"), None);
    }

    #[test]
    fn npm_texts_come_from_the_package_or_the_settings() {
        let packages = [
            npm_package(
                "@scope/dual",
                "Apache-2.0 OR MIT",
                &[
                    ("LICENSE-APACHE-2.0", "Apache terms"),
                    ("LICENSE-MIT", "MIT, by Scope"),
                ],
            ),
            npm_package("plain", "MIT", &[("license", "MIT, by Scope")]),
            npm_package("bare", "MIT", &[]),
        ];
        let npm = merge_npm(&packages, &given(&[("bare", "MIT", "MIT, by Bare\n")])).unwrap();
        assert_eq!(npm.texts.len(), 2);
        let ordered = npm.ordered();
        assert_eq!(
            ordered[0].users,
            names(&["@scope/dual@1.0.0", "plain@1.0.0"])
        );
        assert_eq!(ordered[0].name, "MIT License");
        assert_eq!(ordered[1].text, "MIT, by Bare");
        assert_eq!(npm.packages["@scope/dual@1.0.0"], "Apache-2.0 OR MIT");
    }

    #[test]
    fn npm_text_mistakes_fail() {
        let err = |packages: &[NpmPackage], g: &[(&str, &str, &str)]| {
            merge_npm(packages, &given(g)).unwrap_err().to_string()
        };
        let bare = npm_package("bare", "MIT", &[]);
        assert!(err(&[bare], &[]).contains("bare@1.0.0 ships no license file"));
        let shipped = npm_package("shipped", "MIT", &[("LICENSE", "MIT")]);
        assert!(err(&[shipped], &[("shipped", "MIT", "MIT")]).contains("remove [npm.\"shipped\"]"));
        let bare = npm_package("bare", "MIT OR Apache-2.0", &[]);
        assert!(err(&[bare], &[("bare", "Apache-2.0", "text")]).contains("under MIT"));
        assert!(err(&[], &[("gone", "MIT", "text")]).contains("aren't in the bundle: gone"));
        let gpl = npm_package("gpl", "GPL-3.0-only", &[("COPYING", "GPL")]);
        assert!(err(&[gpl], &[]).contains("gpl@1.0.0 is under GPL-3.0-only"));
        let two = npm_package("two", "MIT", &[("LICENSE", "a"), ("COPYING", "b")]);
        assert!(
            err(&[two], &[]).contains("ships COPYING, LICENSE, and not one file named for MIT")
        );
    }

    #[test]
    fn renders_hand_written_parts_then_sections() {
        let (rust, _) = merge_rust(&two_runs());
        let npm = merge_npm(
            &[npm_package(
                "tick",
                "ISC",
                &[("LICENSE", "ISC with ``` inside\r\n")],
            )],
            &BTreeMap::new(),
        )
        .unwrap();
        let md = render(
            &[
                "# Notices\n\nHeader.\n".to_owned(),
                "## Taken in\n".to_owned(),
            ],
            &rust,
            &npm,
        );
        assert_eq!(
            md,
            "# Notices

Header.

## Taken in

## Rust crates

BeeZip's programs (`BeeZip.exe`, `beezip.exe` and the Explorer menu's DLL) are built for x86_64-pc-windows-msvc from 4 crates, under these licenses. Each text below names the packages it covers; where a package offers a choice of licenses, it is the license BeeZip takes.

| License | Crates |
|---|---:|
| MIT | 3 |
| Apache-2.0 | 1 |
| LicenseRef-UnRAR | 1 |

### MIT License

Used by `a@1.0.0`, `b@2.0.0`.

```text
Copyright (c) A

Permission  is granted.
```

### MIT License

Used by `c@0.1.0`.

```text
Copyright <year> <copyright holders>
```

### Apache License 2.0

Used by `b@2.0.0`.

```text
Apache terms
```

### LicenseRef-UnRAR

Used by `unrar_sys@0.5.8`.

```text
UnRAR's terms
```

## npm packages

BeeZip's interface bundles code from 1 npm packages, under these licenses. Each text below names the packages it covers; where a package offers a choice of licenses, it is the license BeeZip takes.

| License | Packages |
|---|---:|
| ISC | 1 |

### ISC License

Used by `tick@1.0.0`.

````text
ISC with ``` inside
````
"
        );
    }

    #[test]
    fn log_lines_lose_their_colours() {
        assert_eq!(
            plain("2026-11-08T05:42:07Z [\x1b[33mWARN\x1b[0m] failed to validate\x1b[0m"),
            "2026-11-08T05:42:07Z [WARN] failed to validate"
        );
        assert_eq!(plain("plain"), "plain");
    }

    #[test]
    fn settings_parse() {
        let s: Settings = toml::from_str(
            "no-license-file = [\"x\"]\n[npm.\"@a/b\"]\nlicense = \"MIT\"\ntext = '''\nMIT\n'''\n",
        )
        .unwrap();
        assert_eq!(s.no_license_file, names(&["x"]));
        assert_eq!(s.npm["@a/b"].text, "MIT\n");
        assert!(toml::from_str::<Settings>("no-license-file = []\ntypo = 1\n").is_err());
    }
}
