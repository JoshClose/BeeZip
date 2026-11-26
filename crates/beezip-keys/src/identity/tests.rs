//! The store on this system: Windows' DPAPI-NG, macOS's Keychain, a 0600 file elsewhere. Every
//! test works in a folder of its own, and deletes what it kept even when it fails ([`Scratch`]),
//! so the Keychain keeps nothing of a test's.

use beezip_core::format::bhive::crypt::{
    KEY_ID_LEN, MadeSlot, SLOT_TAIL_LEN, SlotKind, SlotView, bech32, x25519, xwing,
};

use super::*;

/// A store in a folder of its own, whose keys are deleted when the test ends.
struct Scratch {
    store: Store,
    _dir: tempfile::TempDir,
}

impl Scratch {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            store: Store::new(dir.path().to_path_buf()),
            _dir: dir,
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Ok(entries) = self.store.list() {
            for e in entries {
                let _ = self.store.delete(&e.name);
            }
        }
    }
}

/// age's own example keys (tests/fixtures/keys/age-spec-examples.txt).
fn age_examples() -> Vec<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/keys/age-spec-examples.txt"
    );
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.trim().to_owned())
        .collect()
}

#[test]
fn keys_round_trip() {
    let s = Scratch::new();
    let pq = s.store.create("Mine", KeyKind::XWing).unwrap();
    assert!(pq.public.starts_with("age1pq1"));
    assert!(pq.own);
    assert_eq!(pq.fingerprint.len(), 19);
    let classic = s.store.create("Classic", KeyKind::X25519).unwrap();
    assert!(classic.public.starts_with("age1") && !classic.public.starts_with("age1pq1"));

    let list = s.store.list().unwrap();
    assert_eq!(list, vec![pq.clone(), classic.clone()]);

    // The public key, and the private one, whose public key is the entry's.
    assert_eq!(*s.store.export("Mine", false).unwrap(), pq.public);
    let secret = s.store.export("mine", true).unwrap();
    assert!(secret.starts_with("AGE-SECRET-KEY-PQ-1"));
    let key = bech32::parse_key(&secret).unwrap();
    assert_eq!(bech32::key_text(&key.public().unwrap()), pq.public);
    assert_eq!(s.store.private("Mine").unwrap(), key);

    // Imported into another store, it is the same key.
    let other = Scratch::new();
    let again = other.store.import("Backup", &secret).unwrap();
    assert_eq!(again.public, pq.public);
    assert_eq!(again.fingerprint, pq.fingerprint);

    s.store.delete("Mine").unwrap();
    assert_eq!(s.store.list().unwrap(), vec![classic]);
    assert_eq!(
        s.store.export("Mine", false).unwrap_err().kind,
        ErrorKind::NotFound
    );
    // Its private key is gone from the system too.
    assert!(seal::get(&s.store.keys_dir(), &record_id(&s.store, &pq.public)).is_err());
}

/// The id a key's private half is kept as.
fn record_id(_: &Store, public: &str) -> String {
    let key = bech32::parse_key(public).unwrap();
    bech32::fingerprint(key.public_bytes().unwrap())
        .replace('-', "")
        .to_lowercase()
}

#[test]
fn ages_keys_import_and_export_as_age_writes_them() {
    let s = Scratch::new();
    let ex = age_examples();
    // An age identity file: comments, then the key.
    let file = format!(
        "# created: 2026-01-01T00:00:00Z\n# public key: {}\n{}\n",
        ex[1], ex[0]
    );
    let mine = s.store.import("age example", &file).unwrap();
    assert!(mine.own);
    assert_eq!(mine.kind, KeyKind::X25519);
    assert_eq!(mine.public, ex[1]);
    assert_eq!(*s.store.export("age example", true).unwrap(), ex[0]);

    let pq = s.store.import("age pq example", &ex[2]).unwrap();
    assert_eq!(pq.kind, KeyKind::XWing);
    assert_eq!(pq.public, ex[3]);

    // Their public keys are contacts' keys elsewhere.
    let other = Scratch::new();
    let contact = other.store.import("Alice", &ex[3]).unwrap();
    assert!(!contact.own);
    assert_eq!(contact.fingerprint, pq.fingerprint);
    assert_eq!(*other.store.export("Alice", false).unwrap(), ex[3]);
    let e = other.store.export("Alice", true).unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidArgs);
    assert!(e.message.contains("contact"), "{}", e.message);
    let found = other
        .store
        .find_public(bech32::parse_key(&ex[3]).unwrap().public_bytes().unwrap())
        .unwrap();
    assert_eq!(found.map(|e| e.name), Some("Alice".into()));
    assert_eq!(other.store.find_public(&[0; 32]).unwrap(), None);
}

#[test]
fn refusals() {
    let s = Scratch::new();
    let ex = age_examples();
    s.store.import("Alice", &ex[1]).unwrap();
    // The same name, whatever its case; the same key under another name.
    assert_eq!(
        s.store.import("ALICE", &ex[3]).unwrap_err().kind,
        ErrorKind::Conflict
    );
    let e = s.store.import("Bob", &ex[1]).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Conflict);
    assert!(e.message.contains("`Alice`"), "{}", e.message);
    // No name, a name too long or with a line break in it.
    for name in ["", "  ", &"x".repeat(101), "a\nb"] {
        assert_eq!(
            s.store.import(name, &ex[3]).unwrap_err().kind,
            ErrorKind::InvalidArgs,
            "{name:?}"
        );
    }
    // A bad checksum, a wrong prefix, mixed case, nothing, two keys.
    let mut bad = ex[3].clone();
    bad.pop();
    bad.push(if ex[3].ends_with('q') { 'p' } else { 'q' });
    let mixed = format!("AGE{}", &ex[3][3..]);
    for text in [
        bad.as_str(),
        "ssh-ed25519 AAAA",
        mixed.as_str(),
        "# only a comment\n",
    ] {
        assert_eq!(
            s.store.import("Carol", text).unwrap_err().kind,
            ErrorKind::InvalidArgs,
            "{text}"
        );
    }
    let two = format!("{}\n{}\n", ex[0], ex[2]);
    assert!(
        s.store
            .import("Carol", &two)
            .unwrap_err()
            .message
            .contains("2 keys")
    );
    assert_eq!(
        s.store.delete("Nobody").unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(s.store.list().unwrap().len(), 1);
}

#[test]
fn a_damaged_or_newer_list_is_refused() {
    let s = Scratch::new();
    std::fs::create_dir_all(s.store.keys_dir()).unwrap();
    std::fs::write(s.store.index_path(), "not json").unwrap();
    assert_eq!(s.store.list().unwrap_err().kind, ErrorKind::Corrupt);
    std::fs::write(s.store.index_path(), r#"{"version": 2, "keys": []}"#).unwrap();
    assert_eq!(
        s.store.list().unwrap_err().kind,
        ErrorKind::UnsupportedFormat
    );
    std::fs::remove_file(s.store.index_path()).unwrap();
    assert!(s.store.list().unwrap().is_empty());
}

#[test]
fn private_keys_are_sealed_on_disk() {
    let s = Scratch::new();
    let e = s.store.create("Mine", KeyKind::XWing).unwrap();
    let secret = s.store.export("Mine", true).unwrap();
    let id = record_id(&s.store, &e.public);
    // Nothing in the folder holds the private key's text or bytes.
    let key = bech32::parse_key(&secret).unwrap();
    let KeyText::XWingSecret(raw) = &key else {
        panic!("an X-Wing key")
    };
    for f in std::fs::read_dir(s.store.keys_dir()).unwrap() {
        let bytes = std::fs::read(f.unwrap().path()).unwrap();
        // Linux keeps the text in a file only you can read.
        let plain_file = cfg!(all(unix, not(target_os = "macos")));
        assert!(plain_file || !bytes.windows(20).any(|w| w == &secret.as_bytes()[..20]));
        assert!(!bytes.windows(32).any(|w| w == &raw[..]));
    }
    #[cfg(windows)]
    {
        let blob = s.store.keys_dir().join(format!("{id}.dpapi"));
        assert!(blob.exists());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = s.store.keys_dir().join(format!("{id}.key"));
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // A key file others can read is refused, as ssh refuses one.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            s.store.export("Mine", true).unwrap_err().kind,
            ErrorKind::Unsafe
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let _ = id;
}

/// A slot of `kind` for `made`, framed as a writer frames it, with its commitment.
fn framed(kind: SlotKind, made: &MadeSlot, key_id: &[u8; KEY_ID_LEN]) -> Vec<u8> {
    let body = u16::try_from(made.public.len() + SLOT_TAIL_LEN).unwrap();
    let mut slot = vec![kind.id(), 0];
    slot.extend(body.to_le_bytes());
    slot.extend(&made.public);
    let probe = SlotView {
        index: 0,
        kind,
        key_id,
        framed: &slot,
        public: &slot[4..],
        commitment: &[0; 32],
    };
    let commitment = x25519::commitment(&probe, made);
    slot.extend(commitment);
    slot.extend([0; 48]);
    slot
}

fn view<'a>(index: usize, key_id: &'a [u8; KEY_ID_LEN], slot: &'a [u8]) -> SlotView<'a> {
    let n = slot.len() - SLOT_TAIL_LEN;
    SlotView {
        index,
        kind: SlotKind::from_id(slot[0]).unwrap(),
        key_id,
        framed: &slot[..n],
        public: &slot[4..n],
        commitment: slot[n..n + 32].try_into().unwrap(),
    }
}

#[test]
fn your_keys_open_the_slots_made_for_them() {
    let s = Scratch::new();
    s.store.create("First", KeyKind::X25519).unwrap();
    let second = s.store.create("Second", KeyKind::X25519).unwrap();
    let pq = s.store.create("Quantum", KeyKind::XWing).unwrap();
    s.store.import("Alice", &age_examples()[3]).unwrap();

    let key_id = [7; KEY_ID_LEN];
    let KeyText::X25519Public(to_second) = bech32::parse_key(&second.public).unwrap() else {
        panic!()
    };
    let KeyText::XWingPublic(to_pq) = bech32::parse_key(&pq.public).unwrap() else {
        panic!()
    };
    let KeyText::XWingPublic(to_alice) = bech32::parse_key(&age_examples()[3]).unwrap() else {
        panic!()
    };
    let slots = [
        framed(
            SlotKind::X25519,
            &x25519::make(&to_second).unwrap(),
            &key_id,
        ),
        framed(SlotKind::XWing, &xwing::make(&to_pq).unwrap(), &key_id),
        // A contact's key: only its holder opens it.
        framed(SlotKind::XWing, &xwing::make(&to_alice).unwrap(), &key_id),
        framed(
            SlotKind::X25519,
            &x25519::make(&x25519::public_of(&[9; 32])).unwrap(),
            &key_id,
        ),
    ];
    let mut source = s.store.source().unwrap();
    for (i, slot) in slots.iter().enumerate() {
        let v = view(i, &key_id, slot);
        let mine = i < 2;
        assert_eq!(source.offers(&v), mine, "slot {i}");
        let secret = source.secret(&v, false).unwrap();
        assert_eq!(secret.is_some(), mine, "slot {i}");
        if let Some(secret) = secret {
            assert!(x25519::commits(&v, &secret), "slot {i}");
        }
    }
    // Asked again, the match is remembered and gives the same answer.
    let v = view(0, &key_id, &slots[0]);
    assert!(source.offers(&v));

    // Other kinds aren't your keys'.
    let mut other = slots[0].clone();
    other[0] = SlotKind::Password.id();
    assert!(!source.offers(&view(0, &key_id, &other)));

    // A store with no keys offers nothing.
    let empty = Scratch::new();
    assert!(!empty.store.source().unwrap().offers(&v));
}

#[test]
fn an_identity_file_opens_its_slots() {
    let ex = age_examples();
    let file = format!(
        "# age's examples
{}

{}
",
        ex[0], ex[2]
    );
    let mut source = identity_file(&file).unwrap();
    let key_id = [1; KEY_ID_LEN];
    let KeyText::XWingPublic(to_pq) = bech32::parse_key(&ex[3]).unwrap() else {
        panic!()
    };
    let KeyText::X25519Public(to_x) = bech32::parse_key(&ex[1]).unwrap() else {
        panic!()
    };
    for slot in [
        framed(SlotKind::XWing, &xwing::make(&to_pq).unwrap(), &key_id),
        framed(SlotKind::X25519, &x25519::make(&to_x).unwrap(), &key_id),
    ] {
        let v = view(0, &key_id, &slot);
        assert!(source.offers(&v));
        assert!(source.secret(&v, false).unwrap().is_some());
    }
    // A public key, or nothing, isn't an identity file.
    let e = identity_file(&format!(
        "{}
{}
",
        ex[0], ex[1]
    ))
    .err()
    .unwrap();
    assert!(e.message.starts_with("line 2:"), "{}", e.message);
    assert!(
        identity_file(
            "# nothing
"
        )
        .is_err()
    );
}
