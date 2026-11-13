//! BeeZip: a sealed volume's file-extent tree (Apple's APFS reference, `fext_tree_key_t` and
//! `fext_tree_val_t`). On a sealed volume (`APFS_INCOMPAT_SEALED_VOLUME`, macOS 11's system
//! volume) a file's extents are kept here, keyed by `(private_id, logical_addr)`, and not in the
//! fs-tree. It's a physical B-tree of fixed-size records, 16-byte keys and values, as the omap
//! is; `apfs_fext_tree_oid` is its root's block.

use super::btree::BTreeNode;
use super::jrec::{FileExtentVal, J_FILE_EXTENT_LEN_MASK};

const KEY: usize = 16;
const VAL: usize = 16;
/// The most nodes read for one file's extents: a damaged tree can't keep the walk going.
const MAX_NODES: usize = 1 << 16;

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// Every extent of the file whose data stream is `private_id`, in `logical_addr` order.
pub fn extents<F>(
    root_paddr: u64,
    block_size: usize,
    private_id: u64,
    read_block: &mut F,
) -> crate::Result<Vec<(u64, FileExtentVal)>>
where
    F: FnMut(u64, &mut [u8]) -> crate::Result<()>,
{
    let mut root = vec![0u8; block_size];
    read_block(root_paddr, &mut root)?;
    let node = BTreeNode::decode(&root)?;
    let (klen, vlen) = node.fixed_kv_size().ok_or_else(|| {
        crate::Error::InvalidImage("apfs: the file-extent tree's root has no btree_info".into())
    })?;
    if klen != KEY || vlen != VAL {
        return Err(crate::Error::InvalidImage(format!(
            "apfs: the file-extent tree's records are ({klen}, {vlen}) bytes, not (16, 16)"
        )));
    }
    let mut out = Vec::new();
    let mut budget = MAX_NODES;
    let above = node.level.saturating_add(1);
    walk(&root, private_id, read_block, &mut out, above, &mut budget)?;
    out.sort_by_key(|(la, _)| *la);
    Ok(out)
}

/// The records under `block` for `private_id`. Levels must fall strictly toward the leaves,
/// below `above`, so a tree that points back up ends.
fn walk<F>(
    block: &[u8],
    private_id: u64,
    read_block: &mut F,
    out: &mut Vec<(u64, FileExtentVal)>,
    above: u16,
    budget: &mut usize,
) -> crate::Result<()>
where
    F: FnMut(u64, &mut [u8]) -> crate::Result<()>,
{
    let node = BTreeNode::decode(block)?;
    if node.level >= above {
        return Err(crate::Error::InvalidImage(
            "apfs: the file-extent tree's levels don't fall toward its leaves".into(),
        ));
    }
    if node.is_leaf() {
        for i in 0..node.nkeys {
            let (k, v) = node.entry_at(i, KEY, VAL)?;
            if k.len() < KEY || v.len() < VAL {
                return Err(crate::Error::InvalidImage(
                    "apfs: a file-extent record is cut short".into(),
                ));
            }
            if le64(k, 0) == private_id {
                out.push((
                    le64(k, 8),
                    FileExtentVal {
                        length: le64(v, 0) & J_FILE_EXTENT_LEN_MASK,
                        phys_block_num: le64(v, 8),
                    },
                ));
            }
        }
        return Ok(());
    }
    // Child i holds the keys from its own up to the next child's.
    let mut children = Vec::with_capacity(node.nkeys as usize);
    for i in 0..node.nkeys {
        let (k, child) = node.child_entry_at(i, KEY)?;
        if k.len() < KEY {
            return Err(crate::Error::InvalidImage(
                "apfs: a file-extent index key is cut short".into(),
            ));
        }
        children.push((le64(k, 0), child));
    }
    for (i, &(first, child)) in children.iter().enumerate() {
        if first > private_id {
            break;
        }
        if children.get(i + 1).is_some_and(|&(next, _)| next < private_id) {
            continue;
        }
        if *budget == 0 {
            return Err(crate::Error::InvalidImage(
                "apfs: the file-extent tree is larger than BeeZip reads for one file".into(),
            ));
        }
        *budget -= 1;
        let mut b = vec![0u8; block.len()];
        read_block(child, &mut b)?;
        walk(&b, private_id, read_block, out, node.level, budget)?;
    }
    Ok(())
}
