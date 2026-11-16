use blake2::{digest::consts::U32, Blake2b, Digest as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use risc0_zkvm::guest::env;
use sha2::Sha256;
use std::io::Read;

fn main() {
    let c0 = env::cycle_count();
    let mut buf = Vec::new();
    env::stdin().read_to_end(&mut buf).unwrap();
    let c1 = env::cycle_count();
    let (key, rest) = buf.split_at(32);
    let (sig, payload) = rest.split_at(64);
    let tx_hash: [u8; 32] = Blake2b::<U32>::digest(payload).into();
    let c2 = env::cycle_count();
    let vk = VerifyingKey::from_bytes(key.try_into().unwrap()).unwrap();
    vk.verify(&tx_hash, &Signature::from_slice(sig).unwrap()).unwrap();
    let c3 = env::cycle_count();
    let block_hash: [u8; 32] = Sha256::digest(payload).into();
    let c4 = env::cycle_count();
    env::commit(&(tx_hash, block_hash));
    env::log(&format!(
        "PHASES bytes={} read={} blake2b={} ed25519={} sha256={} total={}",
        payload.len(),
        c1 - c0,
        c2 - c1,
        c3 - c2,
        c4 - c3,
        env::cycle_count() - c0
    ));
}
