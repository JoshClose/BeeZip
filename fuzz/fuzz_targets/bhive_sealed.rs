//! Opens the input as an encrypted `.bhive` (docs/bhive.md §12): the key block and its slots,
//! a recovery key tried on them, the header MAC, the sealed index, then every entry and the
//! whole archive tested cell by cell, and again from the sealed records. Under a fuzzer every
//! tag, MAC and commitment passes and a sealed part's bytes are its plaintext, so what lies
//! behind them is reached (docs/M14.md §9).

#![no_main]

#[path = "common.rs"]
mod common;

use std::path::Path;

use beezip_core::{
    ArchiveReader, Ctx, Error, ErrorKind, OverwriteChoice, Progress, Result, SimpleCtx,
    format::bhive::{
        BhiveReader,
        crypt::{UnlockAnswer, UnlockRequest},
    },
    source::Source,
};
use libfuzzer_sys::fuzz_target;

/// Answers with a recovery key, once: a password would run Argon2 at whatever cost the input
/// names.
struct Recovery(SimpleCtx);

impl Ctx for Recovery {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn progress(&mut self, p: &Progress) {
        self.0.progress(p);
    }

    fn warn(&mut self, message: String) {
        self.0.warn(message);
    }

    fn password(&mut self, _: Option<&str>, _: u32) -> Result<String> {
        Err(Error::new(ErrorKind::PasswordRequired, "no password"))
    }

    fn overwrite(&mut self, _: &Path) -> Result<OverwriteChoice> {
        Ok(OverwriteChoice::Skip)
    }

    fn unlock(&mut self, request: &UnlockRequest) -> Result<UnlockAnswer> {
        match request.attempt {
            0 => Ok(UnlockAnswer::RecoveryKey(
                "000011-000022-000033-000044-000055-000066-000077-000088".into(),
            )),
            _ => Err(Error::new(ErrorKind::WrongPassword, "wrong key")),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.bhive");
    for recover in [false, true] {
        let opts = beezip_core::OpenOptions {
            recover,
            ..common::open_options()
        };
        let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
            return;
        };
        let mut cx = Recovery(SimpleCtx::new());
        let Ok(mut reader) = BhiveReader::open(source, &mut cx) else {
            continue;
        };
        let _ = reader.unlocked().map(|u| u.descriptions());
        common::exercise(&mut reader, &mut cx.0);
        let _ = reader.test(&mut cx);
    }
});
