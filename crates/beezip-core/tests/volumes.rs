//! Volume sets (docs/M3.md §3.1, §6): reading and seeking across parts, the writer, and sets of
//! every format end to end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use beezip_core::{
    CodecId, CreateOptions, EncodeOpts, ErrorKind, FormatId, FsOptions, OpenOptions,
    OverwritePolicy, Selection, SimpleCtx, WriteSpec, detect_path,
    format::zip::ZipWriteOptions,
    open, ops,
    volume::{VolumeReader, VolumeWriter, find_set, part_path},
};
use proptest::prelude::*;

/// Splits `data` into files `<base>.001`… of the given sizes (the last takes the rest).
fn split(dir: &Path, base: &str, data: &[u8], sizes: &[usize]) -> Vec<PathBuf> {
    let mut parts = Vec::new();
    let mut at = 0;
    for (i, &s) in sizes.iter().enumerate() {
        let end = if i + 1 == sizes.len() {
            data.len()
        } else {
            (at + s).min(data.len())
        };
        let p = dir.join(format!("{base}.{:03}", i + 1));
        fs::write(&p, &data[at..end]).unwrap();
        parts.push(p);
        at = end;
    }
    parts
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn reads_and_seeks_like_the_joined_buffer(
        data in proptest::collection::vec(any::<u8>(), 0..5000),
        sizes in proptest::collection::vec(0usize..1500, 1..8),
        ops in proptest::collection::vec((0u64..6000, 1usize..900), 1..20),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let parts = split(dir.path(), "x", &data, &sizes);
        let mut r = VolumeReader::open(&parts).unwrap();
        prop_assert_eq!(r.len(), data.len() as u64);
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        prop_assert_eq!(&all, &data);
        for (pos, len) in ops {
            let at = r.seek(SeekFrom::Start(pos)).unwrap();
            prop_assert_eq!(at, pos);
            let mut buf = vec![0u8; len];
            let mut got = 0;
            loop {
                let n = r.read(&mut buf[got..]).unwrap();
                if n == 0 { break; }
                got += n;
                if got == len { break; }
            }
            let start = (pos as usize).min(data.len());
            let end = (start + len).min(data.len());
            prop_assert_eq!(&buf[..got], &data[start..end]);
        }
        let end = r.seek(SeekFrom::End(-1)).ok();
        prop_assert_eq!(end, data.len().checked_sub(1).map(|n| n as u64));
    }

    #[test]
    fn the_writer_splits_and_rewrites(
        data in proptest::collection::vec(any::<u8>(), 0..6000),
        size in 1024u64..2500,
        patches in proptest::collection::vec((0u64..6000, proptest::collection::vec(any::<u8>(), 1..700)), 0..6),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("a.bin");
        let mut expected = data.clone();
        let w = VolumeWriter::create(&out, size, false).unwrap();
        let mut h = w.clone();
        h.write_all(&data).unwrap();
        for (pos, bytes) in &patches {
            let pos = (*pos as usize).min(expected.len());
            h.seek(SeekFrom::Start(pos as u64)).unwrap();
            h.write_all(bytes).unwrap();
            let end = pos + bytes.len();
            if end > expected.len() { expected.resize(end, 0); }
            expected[pos..end].copy_from_slice(bytes);
        }
        drop(h);
        let parts = w.finish().unwrap();
        let want = (expected.len() as u64).div_ceil(size).max(1);
        prop_assert_eq!(parts.len() as u64, want);
        for (i, p) in parts.iter().enumerate() {
            let len = fs::metadata(p).unwrap().len();
            if i + 1 < parts.len() { prop_assert_eq!(len, size); }
        }
        let mut joined = Vec::new();
        VolumeReader::open(&parts).unwrap().read_to_end(&mut joined).unwrap();
        prop_assert_eq!(joined, expected);
        // Only the parts are left: no partial files.
        prop_assert_eq!(fs::read_dir(dir.path()).unwrap().count(), parts.len());
    }
}

#[test]
fn a_dropped_writer_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.bin");
    let w = VolumeWriter::create(&out, 1024, false).unwrap();
    w.clone().write_all(&[1u8; 5000]).unwrap();
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 5);
    drop(w);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn overwrite_removes_stale_parts_and_conflicts_without_it() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.bin");
    for n in 1..=4 {
        fs::write(part_path(&out, n), b"old").unwrap();
    }
    let err = VolumeWriter::create(&out, 1024, false).err().unwrap();
    assert_eq!(err.kind, ErrorKind::Conflict);

    let w = VolumeWriter::create(&out, 1024, true).unwrap();
    w.clone().write_all(&[2u8; 1500]).unwrap();
    let parts = w.finish().unwrap();
    assert_eq!(parts.len(), 2);
    assert!(!part_path(&out, 3).exists() && !part_path(&out, 4).exists());
    assert_eq!(find_set(&parts[1]).unwrap().unwrap().parts, parts);

    // A later part in the way, without overwrite: Conflict at finish, and nothing is renamed.
    let other = dir.path().join("b.bin");
    fs::write(part_path(&other, 2), b"old").unwrap();
    let w = VolumeWriter::create(&other, 1024, false).unwrap();
    w.clone().write_all(&[3u8; 1500]).unwrap();
    assert_eq!(w.finish().unwrap_err().kind, ErrorKind::Conflict);
    assert!(!part_path(&other, 1).exists());
    assert!(
        VolumeWriter::create(&other, 1000, false).is_err(),
        "under 1 KiB"
    );
}

/// A small tree to archive.
fn tree(dir: &Path) -> PathBuf {
    let root = dir.join("tree");
    fs::create_dir_all(root.join("sub")).unwrap();
    let mut noise = vec![0u8; 40_000];
    let mut x = 0x2545_F491u32;
    for b in &mut noise {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = x as u8;
    }
    fs::write(root.join("noise.bin"), &noise).unwrap();
    fs::write(root.join("sub/hello.txt"), b"hello volumes\n").unwrap();
    root
}

fn create(out: &Path, input: &Path, spec: &WriteSpec, volume: u64) -> Vec<PathBuf> {
    let opts = CreateOptions {
        volume_size: Some(volume),
        ..CreateOptions::default()
    };
    let report = ops::create(
        out,
        &[input.to_path_buf()],
        spec,
        &opts,
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(report.volumes.len() > 1, "{:?}", report.volumes);
    let total: u64 = report
        .volumes
        .iter()
        .map(|p| fs::metadata(p).unwrap().len())
        .sum();
    assert_eq!(report.bytes_out, total);
    report.volumes
}

fn extract_and_check(part: &Path, input: &Path) {
    let dest = tempfile::tempdir().unwrap();
    ops::extract(
        part,
        dest.path(),
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions {
            overwrite: OverwritePolicy::Always,
            ..FsOptions::default()
        },
        &mut SimpleCtx::new(),
    )
    .unwrap();
    for f in ["noise.bin", "sub/hello.txt"] {
        assert_eq!(
            fs::read(dest.path().join("tree").join(f)).unwrap(),
            fs::read(input.join(f)).unwrap(),
            "{f} from {}",
            part.display()
        );
    }
}

#[test]
fn zip_and_tar_sets_read_from_any_part() {
    let dir = tempfile::tempdir().unwrap();
    let input = tree(dir.path());
    let cases = [
        (
            "a.zip",
            WriteSpec::Zip(ZipWriteOptions::default()),
            FormatId::Zip,
            vec![],
        ),
        (
            "b.tar",
            WriteSpec::Tar {
                codec: None,
                opts: EncodeOpts::default(),
            },
            FormatId::Tar,
            vec![],
        ),
        (
            "c.tar.zst",
            WriteSpec::Tar {
                codec: Some(CodecId::Zstd),
                opts: EncodeOpts::default(),
            },
            FormatId::Tar,
            vec![CodecId::Zstd],
        ),
    ];
    for (name, spec, format, codecs) in cases {
        let parts = create(&dir.path().join(name), &input, &spec, 4096);
        for part in [&parts[0], &parts[parts.len() / 2], parts.last().unwrap()] {
            let det = detect_path(part, &Default::default()).unwrap();
            assert_eq!(det.format(), Some(format), "{name}");
            assert_eq!(det.codecs(), codecs, "{name}");
            assert!(det.joined && det.extension_agrees, "{name}: {det:?}");
            assert_eq!(det.volumes, parts);
            extract_and_check(part, &input);
        }
        let mut cx = SimpleCtx::new();
        let mut opened = open(&parts[1], &OpenOptions::default(), &mut cx).unwrap();
        let total: u64 = parts.iter().map(|p| fs::metadata(p).unwrap().len()).sum();
        assert_eq!(opened.size, total);
        assert_eq!(opened.reader.entries(&mut cx).unwrap().len(), 4, "{name}");
    }
}

#[test]
fn missing_parts() {
    let dir = tempfile::tempdir().unwrap();
    let input = tree(dir.path());
    let parts = create(
        &dir.path().join("a.zip"),
        &input,
        &WriteSpec::Zip(ZipWriteOptions::default()),
        4096,
    );
    assert!(parts.len() >= 4);
    // A missing middle part is NotFound, naming it.
    let middle = parts[2].clone();
    let saved = fs::read(&middle).unwrap();
    fs::remove_file(&middle).unwrap();
    let err = open(&parts[0], &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(
        err.message.contains("volume 3 of a.zip is missing"),
        "{}",
        err.message
    );
    fs::write(&middle, saved).unwrap();
    // A missing last part reads as truncated, and says how many were found.
    fs::remove_file(parts.last().unwrap()).unwrap();
    let err = open(&parts[0], &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
    assert!(
        err.message
            .contains(&format!("{} volumes found", parts.len() - 1)),
        "{err}"
    );
}

#[test]
fn a_split_file_of_anything_else_extracts_joined() {
    let dir = tempfile::tempdir().unwrap();
    let mut data = vec![0u8; 10_000];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i * 7 % 251) as u8;
    }
    let parts = split(dir.path(), "big.iso", &data, &[4000, 4000, 2000]);
    let det = detect_path(&parts[1], &Default::default()).unwrap();
    assert_eq!(det.format(), Some(FormatId::Stream));
    assert!(det.joined);
    let mut cx = SimpleCtx::new();
    let mut opened = open(&parts[2], &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "big.iso");
    assert_eq!(entries[0].size, Some(10_000));
    let dest = tempfile::tempdir().unwrap();
    ops::extract(
        &parts[0],
        dest.path(),
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(fs::read(dest.path().join("big.iso")).unwrap(), data);
}

#[test]
fn spanned_zips_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let input = tree(dir.path());
    let zip = dir.path().join("s.zip");
    ops::create(
        &zip,
        &[input],
        &WriteSpec::Zip(ZipWriteOptions::default()),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    fs::write(dir.path().join("s.z01"), b"part").unwrap();
    let err = open(&zip, &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::UnsupportedFormat);
    assert!(err.message.contains("spanned"), "{err}");
}
