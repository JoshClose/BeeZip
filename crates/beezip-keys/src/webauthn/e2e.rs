//! End to end, with [`MockAuthenticator`] in place of webauthn.dll: archives sealed to a
//! security-key slot or a Windows Hello slot, opened through the envelope with the source as
//! the context's key source, extracted, tested, edited and given another way in.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use beezip_core::{
    ArchiveKind, ConvertOptions, CreateOptions, Ctx, EditOp, EditOptions, ErrorKind, FsOptions,
    OpenOptions, OverwriteChoice, Progress, Result, Selection, SimpleCtx, WriteSpec,
    format::bhive::{
        BhiveReader, BhiveWriteOptions, Level,
        crypt::{
            KeySource, Labelled, Protection, Recipient, SlotKind, Strength, UnlockAnswer,
            UnlockRequest, envelope::KeyBlock,
        },
    },
    ops,
    source::Source,
};
use zeroize::Zeroizing;

use super::{
    Attachment, Fido2Source,
    mock::{Call, MockAuthenticator},
    recipient_with,
};

const HONEY: &str = "honey";

/// A context with nobody at it but the answers it was given, one per attempt, and a key
/// source: the mock's, or for a real device webauthn.dll's. Out of answers, nobody is left to
/// ask, or with `cancel` the Unlock prompt is cancelled. It keeps every request it was asked.
struct DeviceCtx<S = Fido2Source<MockAuthenticator>> {
    source: S,
    answers: Vec<UnlockAnswer>,
    cancel: bool,
    asked: Vec<UnlockRequest>,
}

impl DeviceCtx {
    fn new(auth: MockAuthenticator, answers: Vec<UnlockAnswer>) -> Self {
        Self::with(Fido2Source::new(auth), answers)
    }

    /// What the mock was asked for since it was handed over.
    fn secrets_asked(&self) -> Vec<&Call> {
        self.source
            .authenticator()
            .calls
            .iter()
            .filter(|c| matches!(c, Call::Secret { .. }))
            .collect()
    }

    fn into_authenticator(self) -> MockAuthenticator {
        self.source.into_authenticator()
    }
}

impl<S: KeySource> DeviceCtx<S> {
    fn with(source: S, answers: Vec<UnlockAnswer>) -> Self {
        Self {
            source,
            answers,
            cancel: false,
            asked: Vec::new(),
        }
    }
}

impl<S: KeySource> Ctx for DeviceCtx<S> {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn progress(&mut self, _: &Progress) {}

    fn warn(&mut self, _: String) {}

    fn password(&mut self, _: Option<&str>, _: u32) -> Result<String> {
        Err(beezip_core::Error::new(
            ErrorKind::PasswordRequired,
            "a password is required",
        ))
    }

    fn overwrite(&mut self, existing: &Path) -> Result<OverwriteChoice> {
        Err(beezip_core::Error::new(
            ErrorKind::Conflict,
            format!("`{}` already exists", existing.display()),
        ))
    }

    fn unlock(&mut self, request: &UnlockRequest) -> Result<UnlockAnswer> {
        self.asked.push(request.clone());
        match self.answers.get(request.attempt as usize) {
            Some(answer) => Ok(answer.clone()),
            None if self.cancel => Err(beezip_core::Error::cancelled()),
            None => Err(beezip_core::Error::new(
                ErrorKind::PasswordRequired,
                "nothing left to answer",
            )),
        }
    }

    fn key_source(&mut self) -> Option<&mut dyn KeySource> {
        Some(&mut self.source)
    }
}

/// A password at a cost a test can afford.
fn small(password: &str) -> Labelled {
    Labelled {
        recipient: Recipient::Password {
            password: Zeroizing::new(password.to_owned()),
            strength: Strength::Cost {
                memory_kib: 256,
                passes: 1,
                lanes: 2,
            },
        },
        label: Some("Password".into()),
    }
}

fn labelled(recipient: Recipient, label: &str) -> Labelled {
    Labelled {
        recipient,
        label: Some(label.into()),
    }
}

fn spec(protection: Protection) -> WriteSpec {
    WriteSpec::Bhive(BhiveWriteOptions {
        level: Level::Balanced,
        threads: 2,
        cell_size: Some(16 << 10),
        protection: Some(protection),
        ..BhiveWriteOptions::default()
    })
}

/// A few files under `root/in`: words, noise, an empty one, several cells' worth.
fn tree(root: &Path) -> PathBuf {
    let input = root.join("in");
    fs::create_dir_all(input.join("sub")).unwrap();
    let words: Vec<u8> = b"the bees keep their honey in wax cells "
        .iter()
        .copied()
        .cycle()
        .take(70_000)
        .collect();
    let mut s = 0x9E37_79B9_7F4A_7C15_u64;
    let noise: Vec<u8> = (0..40_000)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect();
    fs::write(input.join("words.txt"), words).unwrap();
    fs::write(input.join("sub/noise.bin"), noise).unwrap();
    fs::write(input.join("sub/empty"), b"").unwrap();
    input
}

/// Every file under `dir`, by its path relative to it.
fn read_tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path.strip_prefix(dir).unwrap().to_string_lossy();
                out.insert(rel.replace('\\', "/"), fs::read(&path).unwrap());
            }
        }
    }
    out
}

fn create(archive: &Path, input: &Path, protection: Protection) -> Result<()> {
    ops::create(
        archive,
        &[input.to_path_buf()],
        &spec(protection),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .map(|_| ())
}

/// The key block as it is in the file.
fn key_block(archive: &Path) -> KeyBlock {
    let bytes = fs::read(archive).unwrap();
    let header: [u8; 16] = bytes[..16].try_into().unwrap();
    KeyBlock::read(&header, &mut &bytes[16..]).unwrap()
}

fn slots(archive: &Path) -> Vec<Vec<u8>> {
    let k = key_block(archive);
    k.slots
        .iter()
        .map(|(_, r)| k.bytes[r.clone()].to_vec())
        .collect()
}

/// Extracts `archive` with `cx`, on four threads, and gives back what came out.
fn extract(archive: &Path, dest: &Path, cx: &mut dyn Ctx) -> Result<BTreeMap<String, Vec<u8>>> {
    let opts = OpenOptions {
        threads: 4,
        min_parallel_files: 1,
        ..OpenOptions::default()
    };
    let report = ops::extract(
        archive,
        dest,
        &Selection::all(),
        &opts,
        FsOptions::default(),
        cx,
    )?;
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    Ok(read_tree(&dest.join("in")))
}

/// A security key: registered and asked once each to make the slot, then asked once for each
/// job that opens the archive, and only after the way was chosen.
#[test]
fn a_security_key_seals_and_opens_an_archive() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    let archive = root.path().join("key.bhive");
    let mut key = MockAuthenticator::new();
    let recipient = recipient_with(&mut key, false, None).unwrap();
    create(
        &archive,
        &input,
        Protection::New(vec![labelled(recipient, "Security key")]),
    )
    .unwrap();
    assert_eq!(key.calls.len(), 2, "{:?}", key.calls);
    let kb = key_block(&archive);
    assert_eq!(kb.slots.len(), 1);
    assert_eq!(kb.slots[0].0, Some(SlotKind::Fido2));
    let bytes = fs::read(&archive).unwrap();
    assert!(
        !bytes.windows(9).any(|w| w == b"words.txt"),
        "a name in the clear"
    );

    // Extracted: the Unlock prompt lists the way in as one this machine has, and the key is
    // asked once, after it was chosen.
    key.calls.clear();
    let mut cx = DeviceCtx::new(key, vec![UnlockAnswer::Way(0)]);
    let got = extract(&archive, &root.path().join("x"), &mut cx).unwrap();
    assert_eq!(got, want);
    assert_eq!(cx.asked.len(), 1);
    let ways = &cx.asked[0].ways;
    assert_eq!(ways.len(), 1);
    assert_eq!(
        (ways[0].slot, ways[0].kind, ways[0].here),
        (0, SlotKind::Fido2, true)
    );
    assert_eq!(
        cx.secrets_asked(),
        [&Call::Secret {
            attachment: Attachment::Any,
            prf: false,
            uv: true,
        }]
    );

    // Tested, and read through the reader: the same one ask each.
    let mut key = cx.into_authenticator();
    key.calls.clear();
    let mut cx = DeviceCtx::new(key, vec![UnlockAnswer::Way(0)]);
    let test = ops::test(
        &archive,
        &Selection::all(),
        &OpenOptions::default(),
        &mut cx,
    )
    .unwrap();
    assert!(test.ok(), "{:?}", test.errors);
    assert_eq!(
        test.bytes,
        want.values().map(|d| d.len() as u64).sum::<u64>()
    );
    assert_eq!(cx.secrets_asked().len(), 1);
    let source = Source::new(&archive, Vec::new(), &OpenOptions::default()).unwrap();
    let r = BhiveReader::open(source, &mut cx).unwrap();
    let unlocked = r.unlocked().unwrap();
    assert_eq!(unlocked.opened_by(), 0);
    let d = unlocked.descriptions().unwrap();
    assert_eq!(d[0].label.as_deref(), Some("Security key"));
    assert!(!d[0].machine_bound, "a security key goes where you go");
    assert_eq!(cx.secrets_asked().len(), 2);

    // Without a key source, nobody can open it, and it says a key is needed.
    let e = ops::test(
        &archive,
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .err()
    .unwrap();
    assert_eq!(e.kind, ErrorKind::KeyRequired, "{}", e.message);
    // With one, but nobody choosing the way, the key is never asked.
    let mut cx = DeviceCtx::new(cx.into_authenticator(), Vec::new());
    let before = cx.secrets_asked().len();
    let e = ops::test(
        &archive,
        &Selection::all(),
        &OpenOptions::default(),
        &mut cx,
    )
    .err()
    .unwrap();
    assert_eq!(e.kind, ErrorKind::KeyRequired, "{}", e.message);
    assert_eq!(cx.secrets_asked().len(), before);
    assert_eq!(cx.asked.len(), 1);
}

/// Another key or a closed dialog doesn't end the open: the Unlock prompt is asked again, and
/// the password, or the key chosen again, opens the archive. Cancelling the Unlock prompt
/// itself ends it; with nobody left to ask, another key leaves the archive closed and says a
/// key is needed. Nothing is extracted from an archive that stays closed.
#[test]
fn after_a_wrong_key_or_a_closed_dialog_it_asks_again() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    let mut key = MockAuthenticator::new();
    let recipient = recipient_with(&mut key, false, None).unwrap();
    let archive = root.path().join("key.bhive");
    create(
        &archive,
        &input,
        Protection::New(vec![labelled(recipient.clone(), "Security key")]),
    )
    .unwrap();
    let both = root.path().join("both.bhive");
    create(
        &both,
        &input,
        Protection::New(vec![labelled(recipient, "Security key"), small(HONEY)]),
    )
    .unwrap();
    let mut closing = key.clone();
    closing.cancel_secrets = true;
    let password_then = |auth: MockAuthenticator| {
        DeviceCtx::new(
            auth,
            vec![UnlockAnswer::Way(0), UnlockAnswer::Password(HONEY.into())],
        )
    };

    // Another key, then the password: asked again, as after a wrong password.
    let mut cx = password_then(MockAuthenticator::new());
    assert_eq!(
        extract(&both, &root.path().join("a"), &mut cx).unwrap(),
        want
    );
    assert_eq!(cx.secrets_asked().len(), 1);
    let attempts: Vec<u32> = cx.asked.iter().map(|r| r.attempt).collect();
    assert_eq!(attempts, [0, 1]);
    assert_eq!(cx.asked[1].ways, cx.asked[0].ways, "the same ways in");

    // Windows Security's dialog closed, then the password.
    let mut cx = password_then(closing.clone());
    assert_eq!(
        extract(&both, &root.path().join("b"), &mut cx).unwrap(),
        want
    );
    assert_eq!(cx.asked.len(), 2);

    // The dialog closed, then the Unlock prompt cancelled: that ends it.
    let dest = root.path().join("x");
    let mut cx = DeviceCtx::new(closing, vec![UnlockAnswer::Way(0)]);
    cx.cancel = true;
    let e = extract(&archive, &dest, &mut cx).err().unwrap();
    assert_eq!(e.kind, ErrorKind::Cancelled, "{}", e.message);
    assert_eq!(cx.asked.len(), 2);
    assert!(!dest.join("in").exists());

    // Another key with nothing else to try: asked again, since the right key may be plugged in
    // now, and with nobody left to ask the archive stays closed for want of a key.
    let mut cx = DeviceCtx::new(MockAuthenticator::new(), vec![UnlockAnswer::Way(0)]);
    let e = extract(&archive, &dest, &mut cx).err().unwrap();
    assert_eq!(e.kind, ErrorKind::KeyRequired, "{}", e.message);
    assert_eq!(cx.secrets_asked().len(), 1);
    assert_eq!(cx.asked.len(), 2);
    assert!(!dest.join("in").exists());

    // A way the archive doesn't have, then a password it has no slot for: neither asks the key.
    key.calls.clear();
    let mut cx = DeviceCtx::new(
        key,
        vec![UnlockAnswer::Way(5), UnlockAnswer::Password(HONEY.into())],
    );
    let e = extract(&archive, &dest, &mut cx).err().unwrap();
    assert_eq!(e.kind, ErrorKind::KeyRequired, "{}", e.message);
    assert!(cx.secrets_asked().is_empty());
    assert!(!dest.join("in").exists());

    // The dialog closed by mistake, and the same way chosen again: the key opens it.
    let key = cx.into_authenticator();
    let mut cx = DeviceCtx::with(
        Fido2Source::new(ClosedOnce {
            inner: key,
            closed: false,
        }),
        vec![UnlockAnswer::Way(0), UnlockAnswer::Way(0)],
    );
    assert_eq!(
        extract(&archive, &root.path().join("c"), &mut cx).unwrap(),
        want
    );
    assert_eq!(cx.asked.len(), 2);
    assert!(cx.source.authenticator().closed);
}

/// The mock, whose first dialog for a secret is closed.
struct ClosedOnce {
    inner: MockAuthenticator,
    closed: bool,
}

impl super::Authenticator for ClosedOnce {
    fn support(&self) -> super::Support {
        self.inner.support()
    }

    fn make_credential(
        &mut self,
        rp_id: &str,
        user_id: &[u8],
        attachment: Attachment,
        prf_salt: Option<&[u8; 32]>,
    ) -> Result<super::NewCredential> {
        self.inner
            .make_credential(rp_id, user_id, attachment, prf_salt)
    }

    fn hmac_secret(&mut self, request: &super::SecretRequest<'_>) -> Result<Zeroizing<[u8; 32]>> {
        if !self.closed {
            self.closed = true;
            return Err(beezip_core::Error::cancelled());
        }
        self.inner.hmac_secret(request)
    }

    fn is_platform_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> bool {
        self.inner.is_platform_credential(rp_id, credential_id)
    }

    fn delete_platform_credential(&mut self, credential_id: &[u8]) -> Result<()> {
        self.inner.delete_platform_credential(credential_id)
    }
}

/// Windows Hello is bound to this PC, so it needs another way in. Opened with it, Hello is
/// asked straight away (its credential is this PC's), with the salt as a PRF input; opened
/// with the password, it is never asked.
#[test]
fn windows_hello_opens_beside_a_password() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    let mut hello = MockAuthenticator::new();
    let recipient = recipient_with(&mut hello, true, None).unwrap();

    let alone = root.path().join("alone.bhive");
    let e = create(
        &alone,
        &input,
        Protection::New(vec![labelled(recipient.clone(), "Windows Hello")]),
    )
    .err()
    .unwrap();
    assert_eq!(e.kind, ErrorKind::InvalidArgs, "{}", e.message);
    assert!(!alone.exists());

    let archive = root.path().join("hello.bhive");
    create(
        &archive,
        &input,
        Protection::New(vec![labelled(recipient, "Windows Hello"), small(HONEY)]),
    )
    .unwrap();
    let kinds: Vec<_> = key_block(&archive).slots.iter().map(|s| s.0).collect();
    assert_eq!(kinds, [Some(SlotKind::Fido2), Some(SlotKind::Password)]);

    hello.calls.clear();
    let mut cx = DeviceCtx::new(hello, vec![UnlockAnswer::Way(0)]);
    let got = extract(&archive, &root.path().join("x"), &mut cx).unwrap();
    assert_eq!(got, want);
    assert_eq!(
        cx.secrets_asked(),
        [&Call::Secret {
            attachment: Attachment::Platform,
            prf: true,
            uv: true,
        }]
    );
    let ways = &cx.asked[0].ways;
    assert_eq!(
        ways.iter()
            .map(|w| (w.slot, w.kind, w.here))
            .collect::<Vec<_>>(),
        [(0, SlotKind::Fido2, true), (1, SlotKind::Password, false)]
    );

    let mut cx = DeviceCtx::new(
        cx.into_authenticator(),
        vec![UnlockAnswer::Password(HONEY.into())],
    );
    let source = Source::new(&archive, Vec::new(), &OpenOptions::default()).unwrap();
    let r = BhiveReader::open(source, &mut cx).unwrap();
    let unlocked = r.unlocked().unwrap();
    assert_eq!(unlocked.opened_by(), 1);
    assert_eq!(cx.secrets_asked().len(), 1, "Hello wasn't asked again");
    let d = unlocked.descriptions().unwrap();
    assert_eq!(d[0].label.as_deref(), Some("Windows Hello"));
    assert!(d[0].machine_bound);
    assert!(!d[1].machine_bound);
}

/// An edit opened with the key keeps its slot byte for byte, and the key opens it again; a
/// security key added to a password archive (as `archive.protect` does) opens it too, under the
/// same file key, and the password still does.
#[test]
fn edits_and_new_ways_in_keep_the_key_working() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    let archive = root.path().join("key.bhive");
    let mut key = MockAuthenticator::new();
    let recipient = recipient_with(&mut key, false, None).unwrap();
    create(
        &archive,
        &input,
        Protection::New(vec![labelled(recipient, "Security key")]),
    )
    .unwrap();
    let before = slots(&archive);

    let extra = root.path().join("more");
    fs::create_dir(&extra).unwrap();
    fs::write(extra.join("new.txt"), b"added later").unwrap();
    let add = EditOp::Add(beezip_core::AddOptions {
        inputs: vec![extra.join("new.txt")],
        ..beezip_core::AddOptions::default()
    });
    key.calls.clear();
    let mut cx = DeviceCtx::new(key, vec![UnlockAnswer::Way(0)]);
    ops::edit(
        &archive,
        &add,
        &mut |_| {
            Ok(WriteSpec::Bhive(BhiveWriteOptions {
                cell_size: Some(16 << 10),
                ..BhiveWriteOptions::default()
            }))
        },
        &EditOptions::default(),
        &mut cx,
    )
    .unwrap();
    assert_eq!(cx.secrets_asked().len(), 1);
    assert_eq!(slots(&archive), before);
    let mut cx = DeviceCtx::new(cx.into_authenticator(), vec![UnlockAnswer::Way(0)]);
    let dest = root.path().join("edited");
    ops::extract(
        &archive,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut cx,
    )
    .unwrap();
    assert_eq!(read_tree(&dest.join("in")), want);
    assert_eq!(fs::read(dest.join("new.txt")).unwrap(), b"added later");
    let mut key = cx.into_authenticator();

    // A password archive given a security key, under its own file key.
    let plain = root.path().join("password.bhive");
    create(&plain, &input, Protection::New(vec![small(HONEY)])).unwrap();
    let source = Source::new(&plain, Vec::new(), &OpenOptions::default()).unwrap();
    let from = BhiveReader::open(source, &mut SimpleCtx::new().with_password(HONEY))
        .unwrap()
        .unlocked()
        .unwrap()
        .clone();
    let recipient = recipient_with(&mut key, false, None).unwrap();
    let changed = root.path().join("changed.bhive");
    ops::convert(
        &plain,
        &changed,
        ArchiveKind::Bhive,
        &spec(Protection::Change {
            from,
            remove: Vec::new(),
            add: vec![labelled(recipient, "Security key")],
        }),
        &ConvertOptions {
            raw: true,
            ..ConvertOptions::default()
        },
        &OpenOptions::default(),
        &mut SimpleCtx::new().with_password(HONEY),
    )
    .unwrap();
    assert_eq!(slots(&changed)[0], slots(&plain)[0]);
    assert_eq!(key_block(&changed).key_id, key_block(&plain).key_id);
    assert_eq!(key_block(&changed).slots[1].0, Some(SlotKind::Fido2));
    key.calls.clear();
    let mut cx = DeviceCtx::new(key, vec![UnlockAnswer::Way(1)]);
    assert_eq!(
        extract(&changed, &root.path().join("y"), &mut cx).unwrap(),
        want
    );
    assert_eq!(cx.secrets_asked().len(), 1);
    let test = ops::test(
        &changed,
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new().with_password(HONEY),
    )
    .unwrap();
    assert!(test.ok(), "{:?}", test.errors);
}

/// The machine's sources, as the commands layer gathers them, with webauthn.dll's among them:
/// its dialogs over the terminal the test runs in, as the CLI's are.
#[cfg(windows)]
fn machine() -> crate::Sources {
    let mut sources = crate::Sources::default();
    sources.push(super::source(crate::console_window()).unwrap());
    sources
}

/// [`a_security_key_seals_and_opens_an_archive`] with a real security key through
/// webauthn.dll: registered, asked for the salt, and asked again to open the archive. Shows
/// Windows' dialog three times, over the terminal the test runs in.
#[cfg(windows)]
#[test]
#[ignore = "needs a person: a FIDO2 security key, its PIN and three touches"]
fn a_real_security_key_seals_and_opens_an_archive() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let archive = root.path().join("key.bhive");
    let recipient = super::recipient(false, None, crate::console_window()).unwrap();
    create(
        &archive,
        &input,
        Protection::New(vec![labelled(recipient, "Security key")]),
    )
    .unwrap();
    let mut cx = DeviceCtx::with(machine(), vec![UnlockAnswer::Way(0)]);
    let got = extract(&archive, &root.path().join("x"), &mut cx).unwrap();
    assert_eq!(got, read_tree(&input));
}

/// The same with Windows Hello beside a password, deleting the credential it registers even
/// when it fails. Shows Windows Hello's prompt three times.
#[cfg(windows)]
#[test]
#[ignore = "needs a person: Windows Hello's face, fingerprint or PIN, three times"]
fn windows_hello_really_opens_an_archive() {
    use super::Authenticator;
    struct Delete(Vec<u8>);
    impl Drop for Delete {
        fn drop(&mut self) {
            let _ = super::win::WebAuthn::new(None).delete_platform_credential(&self.0);
        }
    }
    if !super::support().hello {
        eprintln!("Windows Hello isn't set up here");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let archive = root.path().join("hello.bhive");
    let recipient = super::recipient(true, None, crate::console_window()).unwrap();
    let Recipient::Fido2 { credential_id, .. } = &recipient else {
        panic!("not a security-key recipient");
    };
    let _delete = Delete(credential_id.clone());
    create(
        &archive,
        &input,
        Protection::New(vec![labelled(recipient, "Windows Hello"), small(HONEY)]),
    )
    .unwrap();
    let mut cx = DeviceCtx::with(machine(), vec![UnlockAnswer::Way(0)]);
    let got = extract(&archive, &root.path().join("x"), &mut cx).unwrap();
    assert_eq!(got, read_tree(&input));
}
