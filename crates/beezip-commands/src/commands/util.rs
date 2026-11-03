//! Helpers the commands share.

use std::path::{Path, PathBuf};

use beezip_core::{
    CodecId, OpenOptions, Opened,
    codec::{TAR_SHORTHANDS, strip_extension},
    source::open,
};

use crate::{CmdError, ErrorCode, JobCtx, wire::Secret};

/// `path` made absolute against the current directory, as the CLI's relative paths mean.
pub fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Opens an archive under the job's limits, with the input's password set.
pub fn open_archive(
    path: &Path,
    password: Option<&Secret>,
    cx: &mut JobCtx,
) -> Result<Opened, CmdError> {
    let opts = open_options(cx);
    open_archive_with(path, password, &opts, cx)
}

/// The job's open options. Keep them to share their budget with an `FsSink`.
pub fn open_options(cx: &JobCtx) -> OpenOptions {
    OpenOptions::new(cx.policy().limits.clone())
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
    let name: String = target
        .file_name()
        .map(|n| n.to_string_lossy().chars().take(64).collect())
        .unwrap_or_default();
    let io = |what: &str, e: std::io::Error| CmdError::from(beezip_core::Error::io(what, &e));
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".beezip-partial")
        .rand_bytes(6)
        .tempfile_in(&dir)
        .map_err(|e| io(&format!("creating a file in {}", dir.display()), e))?;
    write(tmp.as_file_mut())?;
    let partial = tmp.into_temp_path();
    std::fs::rename(&partial, target)
        .map_err(|e| io(&format!("writing {}", target.display()), e))?;
    let _ = partial.keep();
    Ok(())
}

/// The archive's name without archive or codec extensions: `a.tar.zst` → `a`, `b.zip` → `b`.
pub fn archive_stem(path: &Path) -> String {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    loop {
        let lower = name.to_lowercase();
        if let Some(c) = CodecId::ALL
            .into_iter()
            .find(|c| c.codec().extensions().iter().any(|e| lower.ends_with(e)))
        {
            match strip_extension(&name, c) {
                Some(stripped) => {
                    name = stripped;
                    continue;
                }
                None => break,
            }
        }
        let ext = beezip_core::format::formats()
            .flat_map(|f| f.extensions().iter())
            .chain(TAR_SHORTHANDS.iter())
            .filter(|e| lower.ends_with(**e) && lower.len() > e.len())
            .max_by_key(|e| e.len());
        match ext {
            Some(e) => name.truncate(name.len() - e.len()),
            None => break,
        }
    }
    if name.is_empty() {
        "archive".into()
    } else {
        name
    }
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
    }
}
