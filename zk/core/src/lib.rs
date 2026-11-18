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

/// `config` names one bridge deployment: Ethereum chain id, vault address and LEZ configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub config: [u8; 32],
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
    pub epoch: u64,
    pub change: Option<KeyChange>,
    pub checkpoint: Checkpoint,
    pub sigs: Vec<(u16, Vec<u8>)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointJournal {
    pub keyset_before: [u8; 32],
    pub keyset_after: [u8; 32],
    pub config: [u8; 32],
    pub channel_id: [u8; 32],
    pub block_id: u64,
    pub block_hash: [u8; 32],
    pub burn_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseInput {
    pub config: [u8; 32],
    pub token: [u8; 20],
    pub nullifier_secret: [u8; 32],
    pub blinding: [u8; 32],
    pub dest: [u8; 20],
    pub fee: u128,
    pub denom: u32,
    pub index: u64,
    pub path: Vec<[u8; 32]>,
}

const RELEASE_HEADER: usize = 32 + 20 + 32 + 32 + 20 + 16 + 4 + 8 + 4;

/// Raw bytes, because serde sends each byte as a 32-bit word and decoding cost most of the proof.
impl ReleaseInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(RELEASE_HEADER + self.path.len() * 32);
        v.extend_from_slice(&self.config);
        v.extend_from_slice(&self.token);
        v.extend_from_slice(&self.nullifier_secret);
        v.extend_from_slice(&self.blinding);
        v.extend_from_slice(&self.dest);
        v.extend_from_slice(&self.fee.to_le_bytes());
        v.extend_from_slice(&self.denom.to_le_bytes());
        v.extend_from_slice(&self.index.to_le_bytes());
        v.extend_from_slice(&(self.path.len() as u32).to_le_bytes());
        for node in &self.path {
            v.extend_from_slice(node);
        }
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < RELEASE_HEADER {
            return None;
        }
        let (h, rest) = b.split_at(RELEASE_HEADER);
        let mut at = 0;
        let mut take = |n: usize| {
            at += n;
            &h[at - n..at]
        };
        let config = take(32).try_into().ok()?;
        let token = take(20).try_into().ok()?;
        let nullifier_secret = take(32).try_into().ok()?;
        let blinding = take(32).try_into().ok()?;
        let dest = take(20).try_into().ok()?;
        let fee = u128::from_le_bytes(take(16).try_into().ok()?);
        let denom = u32::from_le_bytes(take(4).try_into().ok()?);
        let index = u64::from_le_bytes(take(8).try_into().ok()?);
        let depth = u32::from_le_bytes(take(4).try_into().ok()?) as usize;
        if rest.len() != depth * 32 {
            return None;
        }
        let path = rest.chunks_exact(32).map(|c| c.try_into().unwrap()).collect();
        Some(Self { config, token, nullifier_secret, blinding, dest, fee, denom, index, path })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseJournal {
    pub config: [u8; 32],
    pub token: [u8; 20],
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub dest: [u8; 20],
    pub fee: u128,
    pub denom: u32,
    pub depth: u32,
}

/// The epoch keeps a recurring key set distinct, so an old change cannot be replayed.
pub fn keyset_hash(keys: &[Key], threshold: u16, epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KEYSET_DOMAIN);
    h.update(epoch.to_le_bytes());
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
    h.update(c.config);
    h.update(c.channel_id);
    h.update(c.block_id.to_le_bytes());
    h.update(c.block_hash);
    h.update(c.burn_root);
    h.finalize().into()
}

pub fn distinct(keys: &[Key]) -> bool {
    keys.iter().enumerate().all(|(i, k)| !keys[..i].contains(k))
}

/// CONFIG_DOMAIN || epoch u64 || threshold u16 || count u16 || keys || padding the real op would carry.
pub fn encode_config_op(keys: &[Key], threshold: u16, epoch: u64, padding: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(44 + keys.len() * 32 + padding);
    v.extend_from_slice(CONFIG_DOMAIN);
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(&threshold.to_le_bytes());
    v.extend_from_slice(&(keys.len() as u16).to_le_bytes());
    for k in keys {
        v.extend_from_slice(k);
    }
    v.resize(v.len() + padding, 0xAB);
    v
}

/// Refuses a key set that names one key twice, which would let one signer count twice.
pub fn decode_config_op(op: &[u8]) -> Option<(Vec<Key>, u16, u64)> {
    if op.len() < 44 || &op[..32] != CONFIG_DOMAIN {
        return None;
    }
    let epoch = u64::from_le_bytes(op[32..40].try_into().unwrap());
    let threshold = u16::from_le_bytes([op[40], op[41]]);
    let n = u16::from_le_bytes([op[42], op[43]]) as usize;
    if op.len() < 44 + n * 32 {
        return None;
    }
    let keys: Vec<Key> = (0..n)
        .map(|i| op[44 + i * 32..44 + (i + 1) * 32].try_into().unwrap())
        .collect();
    distinct(&keys).then_some((keys, threshold, epoch))
}

pub fn leaf(
    config: &[u8; 32],
    token: &[u8; 20],
    nullifier_secret: &[u8; 32],
    blinding: &[u8; 32],
    dest: &[u8; 20],
    fee: u128,
    denom: u32,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEAF_DOMAIN);
    h.update(config);
    h.update(token);
    h.update(nullifier_secret);
    h.update(blinding);
    h.update(dest);
    h.update(fee.to_le_bytes());
    h.update(denom.to_le_bytes());
    h.finalize().into()
}

pub fn nullifier(config: &[u8; 32], nullifier_secret: &[u8; 32], index: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NULL_DOMAIN);
    h.update(config);
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

/// None when `index` has bits above the depth, which the path ignores but the nullifier hashes.
pub fn root_from_path(mut cur: [u8; 32], index: u64, path: &[[u8; 32]]) -> Option<[u8; 32]> {
    if path.len() >= 64 || index >> path.len() != 0 {
        return None;
    }
    for (level, sib) in path.iter().enumerate() {
        cur = if (index >> level) & 1 == 0 { node(&cur, sib) } else { node(sib, &cur) };
    }
    Some(cur)
}
