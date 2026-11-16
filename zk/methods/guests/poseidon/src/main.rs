use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};
use risc0_zkvm::guest::env;

fn main() {
    let depth: u32 = env::read();
    let c0 = env::cycle_count();
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let c1 = env::cycle_count();
    let mut cur = Fr::from(7u64);
    let sib = Fr::from(11u64);
    for _ in 0..depth {
        cur = hasher.hash(&[cur, sib]).unwrap();
    }
    let c2 = env::cycle_count();
    env::commit(&depth);
    env::log(&format!(
        "PHASES setup={} hashes={} per_hash={} total={}",
        c1 - c0,
        c2 - c1,
        (c2 - c1) / depth.max(1) as u64,
        env::cycle_count() - c0
    ));
}
