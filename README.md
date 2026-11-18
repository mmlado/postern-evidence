# Postern evidence

Measurements behind Moonstruck's proposal for Logos RFP-022, the privacy-preserving wrapped ERC-20 and ether bridge for LEZ. Postern escrows ERC-20s and ether in an Ethereum vault, mints wrapped tokens on LEZ, and releases the original against a LEZ burn proven natively on Ethereum. This spike measures that outbound leg. It was first run on 2026-11-06. On 2026-11-18 three bugs in its guests were fixed and every figure below was measured again, see [Fixed on 18 Nov](#fixed-on-18-nov-2026).

The proposal this evidence supports is [logos-co/rfp#279](https://github.com/logos-co/rfp/issues/279).

## What was measured

A LEZ block reaches Logos Blockchain under one sequencer's signature, so the vault cannot trust a block on its own. In the design measured here, a threshold of the accredited sequencers signs a checkpoint over the bridge's burn root. A checkpoint proof shows those signatures, and the user's release proof shows that their burn is under the checkpointed root and that they hold the burn's secret. Both proofs are RISC Zero receipts, wrapped to Groth16 and verified on Ethereum by RISC Zero's verifier contract.

## Findings

1. **The release proof runs on the user's machine in about 59 seconds at 1.4 GB** on four cores and 8 GB (35 s composite, 24 s succinct). The Groth16 wrap needs x86 Linux, Docker and about 9 GB. The succinct receipt is zero-knowledge, so the user can hand it to a relayer to wrap without revealing the burn's secret.
2. **The checkpoint proof for seven keys at a threshold of five takes about 30 minutes on four cores** (22 min composite, 7.7 min succinct, 1.9 min wrap), from public data alone, so any relayer or signer can produce it on a server. With one change of key set inside it, it takes about 62 minutes (44 min composite, 15.5 min succinct, and a wrap like the others). One checkpoint covers every burn up to its block, so the checkpoint cadence trades release latency against proving cost and adds nothing per burn.
3. **Verifying a receipt on Ethereum costs about 250,200 gas** as a whole transaction (250,176 for a release, 250,152 for a checkpoint, the difference being calldata bytes), of which 223,524 is execution for both. The vault's own logic, such as the nullifier write, the token transfer and the root storage, comes on top and is not measured here.
4. **A SHA-256 burn tree fits in the LEZ bridge program, a Poseidon tree does not.** A depth-32 SHA-256 path with the nullifier costs about 43k cycles, far under the 10M cap on a public LEZ transaction. One Poseidon insert at depth 32 costs 50.8M cycles on light-poseidon, five times the cap.
5. **A Circom release proof over a Poseidon tree proves in 2.1 seconds at 616 MB** and verifies for 241,652 gas. It needs a Poseidon root, which finding 4 rules out inside LEZ, and a phase 2 trusted setup of its own. The proposal keeps RISC Zero, whose Groth16 setup already exists.
6. **Pack the journals.** Guests that commit structs with `env::commit` write every byte of a byte array as a 32-bit word. A packed layout with `env::commit_slice` saves about 1.8k gas per release and 2.5k per checkpoint, and lets Solidity read fields at fixed offsets.
7. **Do not take gas limits from `eth_estimateGas` for a snarkjs verifier.** It returns false instead of reverting when a precompile runs out of gas, so the estimate (36,189) is the gas of a failed check, and a relayer that uses it submits releases that fail. RISC Zero's verifier reverts, so its estimate is safe.

## Fixed on 18 Nov 2026

A review of the guests on 18 Nov found three bugs. The measured costs barely move, but the guests as first published had them:

1. **One burn could be released many times.** The release guest walked the path with the low D bits of the index but hashed all 64 bits into the nullifier, and nothing bounded the index, so index + k·2^D gave the same root with a new nullifier. The guest now refuses an index outside the tree and commits the depth.
2. **A release bound only its denomination.** The leaf, the nullifier and the journal now bind the configuration (Ethereum chain id, vault and LEZ configuration) and the token, so a burn cannot release another token or on another deployment.
3. **The checkpoint guest accepted weak key sets.** It used Ed25519 `verify` instead of `verify_strict`, let one key appear twice in a set so that one holder counted twice, and took a key-set change with no sequence, so an old change could be replayed when a key set came back. It now verifies strictly, refuses a repeated key and requires each change to raise an epoch by one. The checkpoint message and journal also bind the configuration.

`spike1 exec` now runs one refusal case for each, recorded in `results/refusals.json`. The fixes added about 6 percent to the checkpoint and pushed the release past a 2^18 segment, which doubled its proving time. The release guest therefore reads its input as raw bytes instead of serde words, which took it from 216k to 68k cycles. The figures before the fix are in commit 5f6e4a5 and in `results/pre-fix-2026-11-06/`.

## Setup

A desktop (Ryzen 7 5700X3D, 62 GB) limited to four cores (`taskset -c 0-3`, `RAYON_NUM_THREADS=4`) and 8 GB (`systemd-run --scope -p MemoryMax=8G`) as a stand-in for a laptop. RISC Zero 3.0.6 with real proving (`RISC0_DEV_MODE=0`, local prover). The Groth16 wrap in `risczero/risc0-groth16-prover:v2025-04-03.1` under Docker. Circom 2.2.0 with `--O2`, snarkjs 0.7.6 and circomlib 2.0.5, with a local test powers of tau of 2^14, which serves for timing and is not a real ceremony. Gas on anvil (Foundry 1.8.6, hardfork Bpo1) with `RiscZeroGroth16Verifier` from risc0-ethereum v3.0.1, commit 365e7b2.

## Results

Raw data: `results/cycles.json`, `results/logs/*.log` (`/usr/bin/time -v` output), `results/logs/*.docker-mem.log` (wrap container memory), `results/proofs/*.json` and `results/gas.json`. Circom inputs, proofs, verification keys and verifiers are in `circom/build/`.

### Cycles (executor, user cycles)

| Case | Cycles | Notes |
|---|---:|---|
| checkpoint n=3 (t=2) | 1,788,122 | about 856k per strict Ed25519 check, key decompression included |
| checkpoint n=4 (t=3) | 2,651,822 | |
| checkpoint n=5 (t=4) | 3,497,316 | |
| checkpoint n=7 (t=5) | 4,379,197 | |
| checkpoint n=10 (t=7) | 6,151,866 | |
| checkpoint n=16 (t=11) | 9,611,747 | |
| checkpoint n=3 plus key-set change | 3,615,788 | change step 1,749,181 |
| checkpoint n=7 plus key-set change | 8,786,976 | change step 4,327,444 |
| release, SHA-256 tree depth 20 | 50,507 | input decoding 5k |
| release, SHA-256 tree depth 32 | 67,756 | tree and nullifier 43k, input decoding 7k |
| Poseidon (light-poseidon, BN254), one hash | 1,893,557 | 1.58M per hash plus 0.31M setup |
| Poseidon, 32 hashes (one depth-32 insert) | 50,785,803 | five times the 10M public cap |
| one signature over the block, 1 KiB payload | 931,497 | Ed25519 855k |
| one signature over the block, 64 KiB | 4,781,122 | Blake2b 3.67M |
| one signature over the block, 1 MiB | 63,537,868 | Blake2b 58.8M (56 per byte, no accelerator), SHA-256 1.14M, Ed25519 0.84M |

The checkpoint proof and the single-signature cases run off LEZ, so the 10M cap does not bind them. The single-signature rows price a vault that checks one sequencer's signature over a whole block. The Poseidon rows price a Poseidon tree kept by the LEZ bridge program.

### Proving, four cores and 8 GB

| Case | Stage | Segments | Wall time | Peak RSS |
|---|---|---:|---:|---:|
| release depth 32 | composite (one 2^17 segment) | 1 | 35 s | 1.2 GB |
| release depth 32 | succinct | | 24 s | 1.4 GB |
| release depth 32 | Groth16 wrap | | 1 min 59 s | 1.4 GB host, 7.7 GB container |
| checkpoint n=7 | composite, 2^20 segments | | stopped at the 8 GB cap (6 Nov) | over 8 GB |
| checkpoint n=7 | composite, 2^19 segments | 10 | 22 min | 4.8 GB |
| checkpoint n=7 | succinct | | 7.7 min | 1.5 GB |
| checkpoint n=7 | Groth16 wrap | | 1 min 52 s | 1.4 GB host, 8.9 GB container |
| checkpoint n=7 plus change | composite, 2^19 segments | 20 | 44 min | 4.8 GB |
| checkpoint n=7 plus change | succinct | | 15.5 min | 1.5 GB |

Each wrap is about 97 seconds of recursion on the host, then about 15 seconds in the gnark container. The container is not pinned to four cores, and its peak is its cgroup's `memory.peak`, which includes page cache from reading the proving key. The wrap's cost does not depend on the guest, so a wrap of the key-set change case should match the other two. It was not run.

The receipts in `results/proofs` were proved on 18 Nov, after the fix. The container memory figures come from the 6 Nov wraps (`results/logs/*.docker-mem.log`), which match because the wrap does not depend on the guest. The 6 Nov receipts and logs, including a second run of each that matched within 2 percent, are in `results/pre-fix-2026-11-06/`.

### Circom release proof over a Poseidon tree, four cores

| Depth | Constraints (`--O2`) | Prove | Peak RSS |
|---:|---:|---:|---:|
| 20 | 5,421 | 1.75 s | 483 MB |
| 32 | 8,337 | 2.11 s | 616 MB |

SHA-256 in Circom costs 59,313 constraints per tree node (64-byte input) and 89,702 for a 136-byte leaf, so a depth-32 SHA-256 release circuit is about 2.05M constraints and needs a 2^21 powers of tau. Counted, not proved.

### Zero knowledge of a RISC Zero receipt

The prover pads the trace with `ZK_CYCLES = 1024` random rows (risc0-zkp 3.0.5, `src/lib.rs:42`), and the guest's memory image gets 128 bits of host randomness, so the post-state digest leaks nothing (risc0-zkvm 3.0.6, `src/guest/env/mod.rs:133`). The user can therefore prove the succinct receipt on their own machine and hand it to anyone to wrap to Groth16. The wrap runs in RISC Zero's 5.2 GB Docker image on x86 Linux.

### Gas

Whole transactions on anvil, sent with a fixed gas limit of 2M. Execution is the gas used minus 21,000 and the calldata cost.

| Verify call | Gas used | Execution | Calldata | Check |
|---|---:|---:|---:|---|
| RISC Zero `verify(seal, imageId, journalDigest)`, release depth 32 | 250,176 | 223,524 | 420 B | rejects a wrong journal digest |
| RISC Zero, checkpoint n=7 | 250,152 | 223,524 | 420 B | same call shape, so the same execution |
| Circom `verifyProof`, depth 32, five public signals | 241,652 | 214,784 | 420 B | true for the proof, false for a changed public signal |

The pairing math alone computes to about 212k, close to both execution figures.

RISC Zero's `verify` takes only the journal digest. The vault still needs the journal itself to read the root, nullifier and destination, so the journal is calldata on the vault call and is hashed with the SHA-256 precompile.

| Journal | As committed | Packed | Calldata plus SHA-256 saved |
|---|---:|---:|---:|
| release (configuration, token, root, nullifier, destination, fee, denomination, depth) | 568 B | 160 B | about 1.8k gas |
| checkpoint (two key-set hashes, configuration, channel, block id, block hash, burn root) | 776 B | 200 B | about 2.5k gas |

## What is here

| Path | Contents |
|---|---|
| `zk/core` | Shared types: the checkpoint message, key-set hash with its epoch, burn leaf, nullifier, SHA-256 tree with its index bound, and the release input as raw bytes |
| `zk/methods/guests/checkpoint` | t strict Ed25519 checks over a checkpoint bound to one configuration, optionally after one key-set change (Blake2b-256 over a stand-in configuration operation signed at the old threshold, no repeated key, epoch one higher) |
| `zk/methods/guests/release` | Burn leaf bound to the configuration and token, SHA-256 path of depth D with the index inside the tree, nullifier |
| `zk/methods/guests/fallback` | One signature over a block: Blake2b-256 and SHA-256 over a payload plus one Ed25519 check |
| `zk/methods/guests/poseidon` | light-poseidon hashes with circom parameters on BN254, to price a Poseidon tree inside a LEZ program |
| `zk/src/main.rs` | Host: `exec` prints cycles for every case and runs the three refusal cases, `prove` runs one proving stage for one case |
| `circom/` | The release proof as a Groth16 circuit over a Poseidon tree, and SHA-256 node and leaf circuits for constraint counts |
| `gas/` | Forge project that deploys both verifiers on anvil, and `measure.py`, which sends one verify transaction per proof and writes `results/gas.json` |
| `scripts/` | `run-stage.sh` runs one proving stage under the caps, and `setup-gas.sh` fetches the verifier contracts |
| `results/` | Cycles, refusals, logs, receipts and gas from the 18 Nov run, and the 6 Nov run in `pre-fix-2026-11-06/` |

## Rerun it

Cycles and proofs, from `zk/`:

```
cargo build --release
./target/release/spike1 exec
../scripts/run-stage.sh release32 composite
../scripts/run-stage.sh release32 succinct
../scripts/run-stage.sh release32 groth16
SEGMENT_PO2=19 ../scripts/run-stage.sh checkpoint7 composite
SEGMENT_PO2=19 ../scripts/run-stage.sh checkpoint7 succinct
SEGMENT_PO2=19 ../scripts/run-stage.sh checkpoint7 groth16
```

Gas:

```
scripts/setup-gas.sh
anvil
cd gas
forge script script/Deploy.s.sol:Deploy --rpc-url http://127.0.0.1:8545 --private-key <anvil key 0> --broadcast
python3 -I measure.py <R0 address> <C32 address> <anvil key 0>
```

Notes:

- **Image IDs follow the folder.** The guest ELF embeds the absolute path of the guest crates, so a build in another folder gives other image IDs. The receipts in `results/proofs` verify against the image IDs recorded beside them, not against a fresh build here. A deployed vault pins an image ID, so production guests need risc0-build's reproducible Docker build (`RISC0_USE_DOCKER`).
- **Groth16 wrap under SELinux.** Without the `cuda` feature, risc0-groth16 3.0.5 runs `docker run -v <tempdir>:/mnt risczero/risc0-groth16-prover:v2025-04-03.1`. With SELinux enforcing, the container cannot read that mount and Docker exits 1. Set `RISC0_WORK_DIR` to a directory with a shared container label: `chcon -R -t container_file_t -l s0 <dir>`.
- **The wrap container is outside the caps.** It runs under `dockerd`, so neither `MemoryMax=8G` nor `taskset` applies to it, and `/usr/bin/time` does not see it. Its memory was sampled from its cgroup.
- **Circom.** Compile with `--r1cs --wasm --O2` and circomlib 2.0.5 on the include path, then run snarkjs 0.7.6 Groth16 setup against a 2^14 powers of tau. Only the inputs, proofs, verification keys and verifiers are kept, not the proving keys or the powers of tau.

## License

Dual-licensed under MIT and Apache-2.0, at your option.
