//! The malicious CramFS images (docs/M10.md §8), written by core's hand-made CramFS writer
//! (`beezip_core::format::cramfs::write`) and then broken: names that leave the destination; a
//! folder that holds itself; folders nested past 7-Zip's 256; the name mkfs.cramfs wraps to no
//! length; block pointers that go backwards, past the image's end, or claim 4 GiB; and a
//! superblock that counts 2³² - 1 files.

use beezip_core::format::cramfs::write::{Built, Layout, Node, cramfs};

/// A small image: one file of two blocks, one of one, and a folder.
fn small() -> Built {
    cramfs(
        &[
            Node::file(b"two-blocks.bin", &[0x5A; 6000]),
            Node::file(b"safe.txt", b"safe"),
            Node::dir(b"sub", vec![Node::file(b"inner.txt", b"inner")]),
        ],
        &Layout::default(),
    )
}

fn sealed(mut b: Built) -> Vec<u8> {
    b.seal();
    b.image
}

/// `depth` folders, one in the next, with a file at the bottom.
fn nested(depth: usize) -> Vec<u8> {
    let leaf = Node::file(b"bottom.txt", b"bottom");
    let top = (0..depth).fold(leaf, |n, _| Node::dir(b"d", vec![n]));
    cramfs(&[top], &Layout::default()).image
}

/// `(file name, bytes)` for each case.
pub fn corpus() -> anyhow::Result<Vec<(&'static str, Vec<u8>)>> {
    let long = vec![b'n'; 255];
    Ok(vec![
        (
            "traversal.cramfs",
            cramfs(
                &[
                    // One name holding a `/`, and a folder named `..`.
                    Node::file(b"../evil.txt", b"escaped"),
                    Node::dir(b"..", vec![Node::file(b"evil2.txt", b"escaped")]),
                    Node::file(b"safe.txt", b"safe"),
                ],
                &Layout::default(),
            )
            .image,
        ),
        ("cramfs-loop.cramfs", {
            let mut b = small();
            let root = b.inode(b"");
            b.set_inode(b"sub", |i| {
                i.offset = root.offset;
                i.size = root.size;
            });
            sealed(b)
        }),
        ("cramfs-deep.cramfs", nested(300)),
        (
            "cramfs-wrapped-name.cramfs",
            cramfs(
                &[Node::file(&long, b"x"), Node::file(b"after.txt", b"y")],
                &Layout::default(),
            )
            .image,
        ),
        ("cramfs-backwards.cramfs", {
            let mut b = small();
            let t = b.table_at(b"two-blocks.bin");
            let first = b.u32_at(t);
            b.set_u32(t + 4, first - 8);
            sealed(b)
        }),
        ("cramfs-past-end.cramfs", {
            let mut b = small();
            let t = b.table_at(b"two-blocks.bin");
            let first = b.u32_at(t);
            b.set_u32(t + 4, first + 8000);
            sealed(b)
        }),
        ("cramfs-block-4gib.cramfs", {
            let mut b = small();
            let t = b.table_at(b"two-blocks.bin");
            b.set_u32(t, u32::MAX);
            sealed(b)
        }),
        ("cramfs-files-4g.cramfs", {
            let mut b = small();
            b.set_u32(b.base + 44, u32::MAX);
            sealed(b)
        }),
    ])
}
