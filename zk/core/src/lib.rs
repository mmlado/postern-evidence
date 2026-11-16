#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CKPT_DOMAIN: &[u8; 32] = b"/LEZ/bridge/v0/Checkpoint/000000";
pub const KEYSET_DOMAIN: &[u8; 32] = b"/LEZ/bridge/v0/KeySet/0000000000";
pub const CONFIG_DOMAIN: &[u8; 32] = b"/LEZ/bridge/v0/ConfigOp/00000000";
pub const LEAF_DOMAIN: &[u8; 32] = b"/LEZ/bridge/v0/BurnLeaf/00000000";
pub const NULL_DOMAIN: &[u8; 32] = b"/LEZ/bridge/v0/Nullifier/0000000";

pub type Key = [u8; 32];
pub type Sig = [u8; 64];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub channel_id: [u8; 32],
    pub block_id: u64,
    pub block_hash: [u8; 32],
    pub burn_root: [u8; 32],
}

/// Stand-in for a Mantle config op: the guest hashes the bytes with Blake2b-256
/// and reads the new key set out of them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyChange {
    pub op_bytes: Vec<u8>,
    pub sigs: Vec<(u16, Vec<u8>)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointInput {
    pub keys: Vec<Key>,
    pub threshold: u16,
    pub change: Option<KeyChange>,
    pub checkpoint: Checkpoint,
    pub sigs: Vec<(u16, Vec<u8>)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointJournal {
    pub keyset_before: [u8; 32],
    pub keyset_after: [u8; 32],
    pub channel_id: [u8; 32],
    pub block_id: u64,
    pub block_hash: [u8; 32],
    pub burn_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseInput {
    pub nullifier_secret: [u8; 32],
    pub blinding: [u8; 32],
    pub dest: [u8; 20],
    pub fee: u128,
    pub denom: u32,
    pub index: u64,
    pub path: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseJournal {
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub dest: [u8; 20],
    pub fee: u128,
    pub denom: u32,
}

pub fn keyset_hash(keys: &[Key], threshold: u16) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KEYSET_DOMAIN);
    h.update(threshold.to_le_bytes());
    for k in keys {
        h.update(k);
    }
    h.finalize().into()
}

pub fn checkpoint_message(keyset: &[u8; 32], c: &Checkpoint) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CKPT_DOMAIN);
    h.update(keyset);
    h.update(c.channel_id);
    h.update(c.block_id.to_le_bytes());
    h.update(c.block_hash);
    h.update(c.burn_root);
    h.finalize().into()
}

/// CONFIG_DOMAIN || threshold u16 || count u16 || keys || padding the real op would carry.
pub fn encode_config_op(keys: &[Key], threshold: u16, padding: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(36 + keys.len() * 32 + padding);
    v.extend_from_slice(CONFIG_DOMAIN);
    v.extend_from_slice(&threshold.to_le_bytes());
    v.extend_from_slice(&(keys.len() as u16).to_le_bytes());
    for k in keys {
        v.extend_from_slice(k);
    }
    v.resize(v.len() + padding, 0xAB);
    v
}

pub fn decode_config_op(op: &[u8]) -> Option<(Vec<Key>, u16)> {
    if op.len() < 36 || &op[..32] != CONFIG_DOMAIN {
        return None;
    }
    let threshold = u16::from_le_bytes([op[32], op[33]]);
    let n = u16::from_le_bytes([op[34], op[35]]) as usize;
    if op.len() < 36 + n * 32 {
        return None;
    }
    let keys = (0..n)
        .map(|i| op[36 + i * 32..36 + (i + 1) * 32].try_into().unwrap())
        .collect();
    Some((keys, threshold))
}

pub fn leaf(nullifier_secret: &[u8; 32], blinding: &[u8; 32], dest: &[u8; 20], fee: u128, denom: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEAF_DOMAIN);
    h.update(nullifier_secret);
    h.update(blinding);
    h.update(dest);
    h.update(fee.to_le_bytes());
    h.update(denom.to_le_bytes());
    h.finalize().into()
}

pub fn nullifier(nullifier_secret: &[u8; 32], index: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NULL_DOMAIN);
    h.update(nullifier_secret);
    h.update(index.to_le_bytes());
    h.finalize().into()
}

pub fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(l);
    h.update(r);
    h.finalize().into()
}

pub fn root_from_path(mut cur: [u8; 32], index: u64, path: &[[u8; 32]]) -> [u8; 32] {
    for (level, sib) in path.iter().enumerate() {
        cur = if (index >> level) & 1 == 0 { node(&cur, sib) } else { node(sib, &cur) };
    }
    cur
}
