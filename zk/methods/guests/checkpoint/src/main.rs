use blake2::{digest::consts::U32, Blake2b, Digest};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use risc0_zkvm::guest::env;
use spike_core::*;

fn verify_threshold(keys: &[Key], threshold: u16, msg: &[u8; 32], sigs: &[(u16, Vec<u8>)]) {
    assert_eq!(sigs.len(), threshold as usize, "signature count must equal the threshold");
    let mut seen = vec![false; keys.len()];
    for (index, sig) in sigs {
        let i = *index as usize;
        assert!(!seen[i], "duplicate signer");
        seen[i] = true;
        let vk = VerifyingKey::from_bytes(&keys[i]).expect("key");
        let sig = Signature::from_slice(sig).expect("sig");
        vk.verify(msg, &sig).expect("signature");
    }
}

fn main() {
    let c0 = env::cycle_count();
    let input: CheckpointInput = env::read();
    let c1 = env::cycle_count();

    let mut keys = input.keys;
    let mut threshold = input.threshold;
    let keyset_before = keyset_hash(&keys, threshold);

    let mut change_cycles = 0;
    if let Some(change) = input.change {
        let s = env::cycle_count();
        let digest: [u8; 32] = Blake2b::<U32>::digest(&change.op_bytes).into();
        verify_threshold(&keys, threshold, &digest, &change.sigs);
        let (new_keys, new_threshold) = decode_config_op(&change.op_bytes).expect("config op");
        assert!(new_threshold >= 1 && (new_threshold as usize) <= new_keys.len());
        keys = new_keys;
        threshold = new_threshold;
        change_cycles = env::cycle_count() - s;
    }

    let keyset_after = keyset_hash(&keys, threshold);
    let s = env::cycle_count();
    let msg = checkpoint_message(&keyset_after, &input.checkpoint);
    verify_threshold(&keys, threshold, &msg, &input.sigs);
    let sig_cycles = env::cycle_count() - s;

    env::commit(&CheckpointJournal {
        keyset_before,
        keyset_after,
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
