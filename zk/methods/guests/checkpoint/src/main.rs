use blake2::{digest::consts::U32, Blake2b, Digest};
use ed25519_dalek::{Signature, VerifyingKey};
use risc0_zkvm::guest::env;
use spike_core::*;

fn verify_threshold(keys: &[Key], threshold: u16, msg: &[u8; 32], sigs: &[(u16, Vec<u8>)]) {
    assert_eq!(sigs.len(), threshold as usize, "signature count must equal the threshold");
    let mut seen = vec![false; keys.len()];
    for (index, sig) in sigs {
        let i = *index as usize;
        assert!(i < keys.len(), "signer index");
        assert!(!seen[i], "duplicate signer");
        seen[i] = true;
        let vk = VerifyingKey::from_bytes(&keys[i]).expect("key");
        let sig = Signature::from_slice(sig).expect("sig");
        // Strict rejects small-order keys and non-canonical signatures that plain verify accepts.
        vk.verify_strict(msg, &sig).expect("signature");
    }
}

fn main() {
    let c0 = env::cycle_count();
    let input: CheckpointInput = env::read();
    let c1 = env::cycle_count();

    let mut keys = input.keys;
    let mut threshold = input.threshold;
    let mut epoch = input.epoch;
    assert!(distinct(&keys), "duplicate key");
    assert!(threshold >= 1 && (threshold as usize) <= keys.len(), "threshold");
    let keyset_before = keyset_hash(&keys, threshold, epoch);

    let mut change_cycles = 0;
    if let Some(change) = input.change {
        let s = env::cycle_count();
        let digest: [u8; 32] = Blake2b::<U32>::digest(&change.op_bytes).into();
        verify_threshold(&keys, threshold, &digest, &change.sigs);
        let (new_keys, new_threshold, new_epoch) = decode_config_op(&change.op_bytes).expect("config op");
        assert_eq!(new_epoch, epoch + 1, "key-set change out of sequence");
        assert!(new_threshold >= 1 && (new_threshold as usize) <= new_keys.len(), "threshold");
        keys = new_keys;
        threshold = new_threshold;
        epoch = new_epoch;
        change_cycles = env::cycle_count() - s;
    }

    let keyset_after = keyset_hash(&keys, threshold, epoch);
    let s = env::cycle_count();
    let msg = checkpoint_message(&keyset_after, &input.checkpoint);
    verify_threshold(&keys, threshold, &msg, &input.sigs);
    let sig_cycles = env::cycle_count() - s;

    env::commit(&CheckpointJournal {
        keyset_before,
        keyset_after,
        config: input.checkpoint.config,
        channel_id: input.checkpoint.channel_id,
        block_id: input.checkpoint.block_id,
        block_hash: input.checkpoint.block_hash,
        burn_root: input.checkpoint.burn_root,
    });
    env::log(&format!(
        "PHASES decode={} change={} checkpoint_sigs={} total={}",
        c1 - c0,
        change_cycles,
        sig_cycles,
        env::cycle_count() - c0
    ));
}
