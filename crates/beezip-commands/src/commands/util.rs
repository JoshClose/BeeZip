//! Helpers the commands share.

use std::path::{Path, PathBuf};

use std::sync::Arc;

use beezip_core::{NameDecoding, OpenOptions, Opened, safefs::Partial, source::open};

use crate::{
    CmdError, ErrorCode, JobCtx,
    cache::{ArchiveCache, Key, OpenArchive},
    codepages,
    wire::{NameEncoding, Secret},
};

/// `path` made absolute against the current directory, as the CLI's relative paths mean.
pub fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// A volume set's parts named the way `given` (one of them) was: they all sit in its folder,
/// so a relative path gives relative parts (outputs show paths as people wrote them).
pub fn as_given(given: &Path, parts: &[PathBuf]) -> Vec<PathBuf> {
    let dir = given.parent().unwrap_or(Path::new(""));
    parts
        .iter()
        .map(|p| match p.file_name() {
            Some(name) => dir.join(name),
            None => p.clone(),
        })
        .collect()
}

/// Opens an archive under the job's limits, with the input's password set.
pub fn open_archive(
    path: &Path,
    password: Option<&Secret>,
    encoding: Option<NameEncoding>,
    cx: &mut JobCtx,
) -> Result<Opened, CmdError> {
    let opts = open_options(encoding, cx);
    open_archive_with(path, password, &opts, cx)
}

/// The job's open options, reading names in `encoding` (else the config's). Keep them to share
/// their budget with an `FsSink`.
pub fn open_options(encoding: Option<NameEncoding>, cx: &JobCtx) -> OpenOptions {
    OpenOptions::new(cx.policy().limits.clone()).with_names(names(encoding, cx))
}

/// How names are read: in `encoding`, else in `[names] encoding`, on this system's code pages.
/// A config that can't be read gives "auto", as its limits give the defaults.
pub fn names(encoding: Option<NameEncoding>, cx: &JobCtx) -> NameDecoding {
    let encoding = encoding
        .or_else(|| cx.config().ok().map(|c| c.names.encoding))
        .unwrap_or_default();
    codepages::decoding(encoding.into())
}

pub fn open_archive_with(
    path: &Path,
    password: Option<&Secret>,
    opts: &OpenOptions,
    cx: &mut JobCtx,
) -> Result<Opened, CmdError> {
    cx.set_password(password);
    Ok(open(&absolute(path), opts, cx)?)
}

/// An archive lent from the engine's cache, or opened for this job.
struct Lent {
    archive: OpenArchive,
    home: Option<(Arc<ArchiveCache>, Key)>,
}

impl Lent {
    /// Back to the cache, unless a password reached the reader or the job was cancelled.
    fn give_back(self, cx: &JobCtx) {
        if let Some((cache, key)) = self.home
            && !cx.password_used()
            && !cx.is_cancelled()
        {
            cache.give_back(key, self.archive);
        }
    }
}

/// Runs `f` on the archive at `path`, lent from the engine's archive cache (docs/M3.md §4.2)
/// or opened. It goes back afterwards, unless the job was cancelled, a password reached the
/// reader, or `f` failed reading it; an error about the arguments keeps it.
pub fn with_archive<T>(
    path: &Path,
    password: Option<&Secret>,
    encoding: Option<NameEncoding>,
    cx: &mut JobCtx,
    f: impl FnOnce(&mut OpenArchive, &mut JobCtx) -> Result<T, CmdError>,
) -> Result<T, CmdError> {
    let mut lent = open_lent(path, password, encoding, cx)?;
    let result = f(&mut lent.archive, cx);
    let keep = match &result {
        Ok(_) => true,
        Err(e) => matches!(
            e.code,
            ErrorCode::InvalidArgs | ErrorCode::NotFound | ErrorCode::UnsupportedOperation
        ),
    };
    if keep {
        lent.give_back(cx);
    }
    result
}

fn open_lent(
    path: &Path,
    password: Option<&Secret>,
    encoding: Option<NameEncoding>,
    cx: &mut JobCtx,
) -> Result<Lent, CmdError> {
    cx.set_password(password);
    let path = absolute(path);
    let limits = cx.policy().limits.clone();
    let names = names(encoding, cx);
    let cache = cx.cache().cloned();
    let canonical = std::fs::canonicalize(&path).ok();
    if let (Some(cache), Some(canonical)) = (&cache, &canonical)
        && let Some((archive, key)) = cache.lend(canonical, &limits, &names)
    {
        return Ok(Lent {
            archive,
            home: Some((Arc::clone(cache), key)),
        });
    }
    let opts = OpenOptions::new(limits.clone()).with_names(names);
    let opened = open(&path, &opts, cx)?;
    let home = match (cache, canonical) {
        (Some(cache), Some(canonical)) => {
            Key::new(canonical, limits, names, &opened.detection.volumes).map(|key| (cache, key))
        }
        _ => None,
    };
    Ok(Lent {
        archive: OpenArchive::new(opened, opts.budget),
        home,
    })
}

/// Writes `target` through `<name>.<random>.beezip-partial` in its directory and renames it into
/// place when `write` succeeds. On failure or cancellation the partial file is deleted.
pub fn write_atomically(
    target: &Path,
    write: impl FnOnce(&mut std::fs::File) -> Result<(), CmdError>,
) -> Result<(), CmdError> {
    let dir = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut tmp = Partial::create(&dir, &format!(".{name}"))?;
    write(tmp.file_mut())?;
    tmp.persist(target)?;
    Ok(())
}

/// The archive's name without archive or codec extensions: `a.tar.zst` → `a`, `b.zip` → `b`,
/// `a.part1.rar` → `a`. The Explorer menu's titles use the same function (docs/M4.md §3.2).
pub fn archive_stem(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    beezip_menu::archive_stem(&name)
}

/// Fails with `Conflict` if `path` exists and `overwrite` isn't set.
pub fn check_output(path: &Path, overwrite: bool) -> Result<(), CmdError> {
    if !overwrite && std::fs::symlink_metadata(path).is_ok() {
        return Err(CmdError::new(
            ErrorCode::Conflict,
            format!(
                "`{}` already exists; set `overwrite` (--overwrite) to replace it",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// A level for `name` (a codec or zip method): the input's, else the config's, else none.
pub fn level(input: Option<i32>, name: &str, cx: &JobCtx) -> Result<Option<i32>, CmdError> {
    Ok(match input {
        Some(l) => Some(l),
        None => cx.config()?.level(name),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use clap::{Args, FromArgMatches};
    use serde::{Serialize, de::DeserializeOwned};

    /// The CLI with only `args` and JSON with only `json` give the same input: the defaults on
    /// both sides agree (docs/M1.md §4.2).
    pub(crate) fn cli_matches_json<T>(args: &[&str], json: serde_json::Value)
    where
        T: Args + FromArgMatches + Serialize + DeserializeOwned,
    {
        let cmd = T::augment_args(clap::Command::new("t").no_binary_name(true));
        let matches = cmd.try_get_matches_from(args).expect("the CLI parses");
        let from_cli = T::from_arg_matches(&matches).expect("the CLI builds the input");
        let from_json: T = serde_json::from_value(json).expect("the JSON builds the input");
        assert_eq!(
            serde_json::to_value(&from_cli).unwrap(),
            serde_json::to_value(&from_json).unwrap()
        );
    }

    #[test]
    fn stems() {
        use std::path::Path;
        let s = |p: &str| super::archive_stem(Path::new(p));
        assert_eq!(s("a.tar.zst"), "a");
        assert_eq!(s("b.zip"), "b");
        assert_eq!(s("c.tgz"), "c");
        assert_eq!(s("notes.txt.gz"), "notes.txt");
        assert_eq!(s("d.e.zip"), "d.e");
        assert_eq!(s(".zip"), ".zip");
        assert_eq!(s("e.tar.zst.002"), "e");
        assert_eq!(s("big.iso.001"), "big.iso");
        assert_eq!(s("a.part1.rar"), "a");
    }

    /// beezip-menu knows extensions from a generated list (`cargo xtask codegen`), not from
    /// core. Every extension core reads must be an archive to the menu, and lose itself in a
    /// stem, so a stale list fails here as well as in `codegen --check`.
    #[test]
    fn the_menu_knows_every_extension_core_reads() {
        use beezip_core::{CodecId, codec::TAR_SHORTHANDS};
        let formats = beezip_core::format::formats().flat_map(|f| f.extensions().iter());
        let codecs = CodecId::ALL
            .into_iter()
            .flat_map(|c| c.codec().extensions().iter());
        for ext in formats.chain(codecs).chain(TAR_SHORTHANDS.iter()) {
            let name = format!("name{ext}");
            assert!(beezip_menu::is_archive(&name), "{name}");
            assert_eq!(beezip_menu::archive_stem(&name), "name", "{name}");
        }
    }
}
