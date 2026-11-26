//! `archive.sign` (docs/M14.md §11): signs a `.bhive` in place, or removes its signatures,
//! without changing its contents. The new file is written beside it and swapped in, as every
//! edit is; only the index changes.

use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use super::swap;
use crate::{
    Ctx, Error, Result,
    format::bhive::{
        BhiveReader,
        layout::{self, FEATURE_ENCRYPTED, HEADER_LEN, MAGIC},
        sign::{
            Report, Signing,
            edit::{Resign, resign},
        },
    },
    io::write_error,
    source::{OpenOptions, Source},
};

/// What to sign with, and what to remove.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// How to open the archive: its limits. An encrypted one is opened with what the job's
    /// context answers, as any reader is.
    pub open: OpenOptions,
    /// New signatures, by these signers.
    pub signing: Signing,
    /// Signatures removed, by their place in the archive's list (from 0).
    pub remove: Vec<usize>,
    /// Remove every signature first.
    pub remove_all: bool,
}

/// What `archive.sign` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignReport {
    /// The canonical path of the archive written.
    pub path: PathBuf,
    /// The signatures afterwards, checked.
    pub signatures: Report,
    pub added: usize,
    /// The signatures the archive no longer has, those over digests made again among them.
    pub removed: usize,
    /// The cells' digests were made: the archive had none. (Adding a signature reads every
    /// cell once either way.)
    pub hashed: bool,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

/// Signs `archive` with `opts.signing`, after removing the signatures `opts` names. The
/// signatures kept still verify: the contents don't change.
pub fn sign(archive: &Path, opts: &SignOptions, cx: &mut dyn Ctx) -> Result<SignReport> {
    if opts.signing.is_empty() && opts.remove.is_empty() && !opts.remove_all {
        return Err(Error::invalid_args(
            "nothing to do: give a signer, or the signatures to remove",
        ));
    }
    let target = swap::Target::check(archive)?;
    let name = target.name.clone();
    let mut input = BufReader::new(
        File::open(&target.path).map_err(|e| Error::io(format!("opening {name}"), &e))?,
    );
    // Only a .bhive; the rest (its index whole, not recovered) is checked as it is read.
    let mut head = [0u8; HEADER_LEN];
    if input.read_exact(&mut head).is_err() || !head.starts_with(&MAGIC) {
        return Err(Error::unsupported(format!(
            "{name} isn't a .bhive; only a .bhive can be signed"
        )));
    }
    // An encrypted archive is opened first, with a way in, for its keys: its index is sealed.
    let unlocked = if layout::check_header(&head)? & FEATURE_ENCRYPTED != 0 {
        let open = OpenOptions {
            recover: false,
            ..opts.open.clone()
        };
        let source = Source::new(&target.path, Vec::new(), &open)?;
        let reader = BhiveReader::open(source, cx)?;
        reader.unlocked().cloned()
    } else {
        None
    };
    let what = Resign {
        signing: opts.signing.clone(),
        remove: opts.remove.clone(),
        remove_all: opts.remove_all,
        limits: opts.open.limits.clone(),
        unlocked,
    };
    let mut partial = target.partial()?;
    let done = {
        let mut out = BufWriter::new(partial.file_mut());
        let done = resign(&mut input, &mut out, &what, cx)?;
        out.flush().map_err(|e| write_error(&e))?;
        done
    };
    drop(input);
    target.swap(partial, cx)?;
    Ok(SignReport {
        bytes_after: std::fs::metadata(&target.path)
            .map(|m| m.len())
            .unwrap_or(0),
        path: target.path,
        signatures: done.report,
        added: done.added,
        removed: done.removed,
        hashed: done.hashed,
        bytes_before: target.stamp.size,
    })
}
