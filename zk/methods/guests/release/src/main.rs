use risc0_zkvm::guest::env;
use spike_core::*;

fn main() {
    let c0 = env::cycle_count();
    let input: ReleaseInput = env::read();
    let c1 = env::cycle_count();
    let leaf = leaf(&input.nullifier_secret, &input.blinding, &input.dest, input.fee, input.denom);
    let root = root_from_path(leaf, input.index, &input.path);
    let nullifier = nullifier(&input.nullifier_secret, input.index);
    let c2 = env::cycle_count();
    env::commit(&ReleaseJournal { root, nullifier, dest: input.dest, fee: input.fee, denom: input.denom });
    env::log(&format!("PHASES decode={} tree={} total={}", c1 - c0, c2 - c1, env::cycle_count() - c0));
}
