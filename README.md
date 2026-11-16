# Postern evidence

Measurements behind Moonstruck's proposal for Logos RFP-022, the privacy-preserving wrapped ERC-20 and ether bridge for LEZ. Postern escrows ERC-20s and ether in an Ethereum vault, mints wrapped tokens on LEZ, and releases the original against a LEZ burn proven natively on Ethereum. This spike measures that outbound leg. It was run on 2026-11-06, before filing.

The proposal this evidence supports is [logos-co/rfp#NNN](https://github.com/logos-co/rfp/issues/NNN).

## What was measured

A LEZ block reaches Logos Blockchain under one sequencer's signature, so the vault cannot trust a block on its own. In the design measured here, a threshold of the accredited sequencers signs a checkpoint over the bridge's burn root. A checkpoint proof shows those signatures, and the user's release proof shows that their burn is under the checkpointed root and that they hold the burn's secret. Both proofs are RISC Zero receipts, wrapped to Groth16 and verified on Ethereum by RISC Zero's verifier contract.

## Findings

1. **The release proof runs on the user's machine in about 95 seconds at 2.4 GB** on four cores and 8 GB (71 s composite, 24 s succinct). The Groth16 wrap needs x86 Linux, Docker and about 9 GB. The succinct receipt is zero-knowledge, so the user can hand it to a relayer to wrap without revealing the burn's secret.
2. **The checkpoint proof for seven keys at a threshold of five takes about 30 minutes on four cores** (21 min composite, 6.9 min succinct, 1.8 min wrap), from public data alone, so any relayer or signer can produce it on a server. With one change of key set inside it, it takes about 57 minutes. One checkpoint covers every burn up to its block, so the checkpoint cadence trades release latency against proving cost and adds nothing per burn.
3. **Verifying a receipt on Ethereum costs 250,164 gas** as a whole transaction, the same for a release and a checkpoint. The vault's own logic, such as the nullifier write, the token transfer and the root storage, comes on top and is not measured here.
4. **A SHA-256 burn tree fits in the LEZ bridge program, a Poseidon tree does not.** A depth-32 SHA-256 path with the nullifier costs about 42k cycles, far under the 10M cap on a public LEZ transaction. One Poseidon insert at depth 32 costs 50.8M cycles on light-poseidon, five times the cap.
5. **A Circom release proof over a Poseidon tree proves in 2.1 seconds at 616 MB** and verifies for 241,652 gas. It needs a Poseidon root, which finding 4 rules out inside LEZ, and a phase 2 trusted setup of its own. The proposal keeps RISC Zero, whose Groth16 setup already exists.
6. **Pack the journals.** Guests that commit structs with `env::commit` write every byte of a byte array as a 32-bit word. A packed layout with `env::commit_slice` saves about 1k gas per release and 2k per checkpoint, and lets Solidity read fields at fixed offsets.
7. **Do not take gas limits from `eth_estimateGas` for a snarkjs verifier.** It returns false instead of reverting when a precompile runs out of gas, so the estimate (36,189) is the gas of a failed check, and a relayer that uses it submits releases that fail. RISC Zero's verifier reverts, so its estimate is safe.

## Setup

A desktop (Ryzen 7 5700X3D, 62 GB) limited to four cores (`taskset -c 0-3`, `RAYON_NUM_THREADS=4`) and 8 GB (`systemd-run --scope -p MemoryMax=8G`) as a stand-in for a laptop. RISC Zero 3.0.6 with real proving (`RISC0_DEV_MODE=0`, local prover). The Groth16 wrap in `risczero/risc0-groth16-prover:v2025-04-03.1` under Docker. Circom 2.2.0 with `--O2`, snarkjs 0.7.6 and circomlib 2.0.5, with a local test powers of tau of 2^14, which serves for timing and is not a real ceremony. Gas on anvil (Foundry 1.8.6, hardfork Bpo1) with `RiscZeroGroth16Verifier` from risc0-ethereum v3.0.1, commit 365e7b2.

## Results

Raw data: `results/cycles.json`, `results/logs/*.log` (`/usr/bin/time -v` output), `results/logs/*.docker-mem.log` (wrap container memory), `results/proofs/*.json` and `results/gas.json`. Circom inputs, proofs, verification keys and verifiers are in `circom/build/`.

### Cycles (executor, user cycles)

| Case | Cycles | Notes |
|---|---:|---|
| checkpoint n=3 (t=2) | 1,663,188 | about 800k per Ed25519 check, key decompression included |
| checkpoint n=4 (t=3) | 2,492,695 | |
| checkpoint n=5 (t=4) | 3,316,809 | |
| checkpoint n=7 (t=5) | 4,126,541 | |
| checkpoint n=10 (t=7) | 5,743,162 | |
| checkpoint n=16 (t=11) | 8,984,927 | |
| checkpoint n=3 plus key-set change | 3,361,039 | change step 1,625,097 |
| checkpoint n=7 plus key-set change | 8,265,200 | change step 4,044,341 |
| release, SHA-256 tree depth 20 | 145,644 | 105k of it is input decoding |
| release, SHA-256 tree depth 32 | 216,120 | tree and nullifier 42k, input decoding 161k |
| Poseidon (light-poseidon, BN254), one hash | 1,893,557 | 1.58M per hash plus 0.31M setup |
| Poseidon, 32 hashes (one depth-32 insert) | 50,785,803 | five times the 10M public cap |
| one signature over the block, 1 KiB payload | 931,497 | Ed25519 855k |
| one signature over the block, 64 KiB | 4,781,122 | Blake2b 3.67M |
| one signature over the block, 1 MiB | 63,537,868 | Blake2b 58.8M (56 per byte, no accelerator), SHA-256 1.14M, Ed25519 0.84M |

The checkpoint proof and the single-signature cases run off LEZ, so the 10M cap does not bind them. The single-signature rows price a vault that checks one sequencer's signature over a whole block. The Poseidon rows price a Poseidon tree kept by the LEZ bridge program.

### Proving, four cores and 8 GB

| Case | Stage | Segments | Wall time | Peak RSS |
|---|---|---:|---:|---:|
| release depth 32 | composite (2^20 segments) | 1 | 71 s | 2.4 GB |
| release depth 32 | succinct | | 24 s | 1.4 GB |
| release depth 32 | Groth16 wrap | | 1 min 52 s | 1.4 GB host, 7.7 GB container |
| checkpoint n=7 | composite, 2^20 segments | | stopped at the 8 GB cap | over 8 GB |
| checkpoint n=7 | composite, 2^19 segments | 9 | 21 min | 4.8 GB |
| checkpoint n=7 | succinct | | 6.9 min | 1.5 GB |
| checkpoint n=7 | Groth16 wrap | | 1 min 50 s | 1.4 GB host, 8.9 GB container |
| checkpoint n=7 plus change | composite, 2^19 segments | 18 | 41 min | 4.8 GB |
| checkpoint n=7 plus change | succinct | | 14.3 min | 1.5 GB |

Each wrap is about 97 seconds of recursion on the host, then about 15 seconds in the gnark container. The container is not pinned to four cores, and its peak is its cgroup's `memory.peak`, which includes page cache from reading the proving key. The wrap's cost does not depend on the guest, so a wrap of the key-set change case should match the other two. It was not run.

All receipts were proved twice, and the times matched within 2 percent. The first-run logs are kept as `*.pre-move.log`. The succinct receipt of the key-set change case failed its final check after a rebuild changed its image ID, so it is not kept. Its time stands, because compression does not depend on the image ID.

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
| RISC Zero `verify(seal, imageId, journalDigest)`, release depth 32 | 250,164 | 223,524 | 420 B | rejects a wrong journal digest |
| RISC Zero, checkpoint n=7 | 250,164 | 223,524 | 420 B | same call shape, so the same gas |
| Circom `verifyProof`, depth 32, five public signals | 241,652 | 214,784 | 420 B | true for the proof, false for a changed public signal |

The pairing math alone computes to about 212k, close to both execution figures.

RISC Zero's `verify` takes only the journal digest. The vault still needs the journal itself to read the root, nullifier and destination, so the journal is calldata on the vault call and is hashed with the SHA-256 precompile.

| Journal | As committed | Packed | Calldata plus SHA-256 saved |
|---|---:|---:|---:|
| release (root, nullifier, destination, fee, denomination) | 356 B | 104 B | about 1.1k gas |
| checkpoint (two key-set hashes, channel, block id, block hash, burn root) | 648 B | 168 B | about 2.1k gas |

## What is here

| Path | Contents |
|---|---|
| `zk/core` | Shared types: the checkpoint message, key-set hash, burn leaf, nullifier and SHA-256 tree |
| `zk/methods/guests/checkpoint` | t Ed25519 checks over a checkpoint, optionally after one key-set change (Blake2b-256 over a stand-in configuration operation signed at the old threshold) |
| `zk/methods/guests/release` | Burn leaf, SHA-256 path of depth D, nullifier |
| `zk/methods/guests/fallback` | One signature over a block: Blake2b-256 and SHA-256 over a payload plus one Ed25519 check |
| `zk/methods/guests/poseidon` | light-poseidon hashes with circom parameters on BN254, to price a Poseidon tree inside a LEZ program |
| `zk/src/main.rs` | Host: `exec` prints cycles for every case, `prove` runs one proving stage for one case |
| `circom/` | The release proof as a Groth16 circuit over a Poseidon tree, and SHA-256 node and leaf circuits for constraint counts |
| `gas/` | Forge project that deploys both verifiers on anvil, and `measure.py`, which sends one verify transaction per proof and writes `results/gas.json` |
| `scripts/` | `run-stage.sh` runs one proving stage under the caps, and `setup-gas.sh` fetches the verifier contracts |
| `results/` | Cycles, logs, receipts and gas from our runs |

## Rerun it

Cycles and proofs, from `zk/`:

```
cargo build --release
./target/release/spike1 exec
../scripts/run-stage.sh release32 composite
../scripts/run-stage.sh release32 succinct
../scripts/run-stage.sh release32 groth16
SEGMENT_PO2=19 ../scripts/run-stage.sh checkpoint7 composite
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
