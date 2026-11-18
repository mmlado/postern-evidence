use risc0_zkvm::guest::env;
use spike_core::*;
use std::io::Read;

fn main() {
    let c0 = env::cycle_count();
    let mut buf = Vec::new();
    env::stdin().read_to_end(&mut buf).unwrap();
    let input = ReleaseInput::from_bytes(&buf).expect("release input");
    let c1 = env::cycle_count();
    let leaf = leaf(
        &input.config,
        &input.token,
        &input.nullifier_secret,
        &input.blinding,
        &input.dest,
        input.fee,
        input.denom,
    );
    let root = root_from_path(leaf, input.index, &input.path).expect("index outside the tree");
    let nullifier = nullifier(&input.config, &input.nullifier_secret, input.index);
    let c2 = env::cycle_count();
    env::commit(&ReleaseJournal {
        config: input.config,
        token: input.token,
        root,
        nullifier,
        dest: input.dest,
        fee: input.fee,
        denom: input.denom,
        depth: input.path.len() as u32,
    });
    env::log(&format!("PHASES decode={} tree={} total={}", c1 - c0, c2 - c1, env::cycle_count() - c0));
}
