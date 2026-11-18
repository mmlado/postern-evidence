use std::{fs, path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, Receipt};
use spike_core::*;
use spike_methods::*;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Executor only: cycles for every case.
    Exec,
    /// One proving stage for one case, receipts kept in --dir between stages.
    Prove {
        #[arg(long)]
        case: String,
        /// composite, succinct or groth16
        #[arg(long)]
        stage: String,
        #[arg(long, default_value = "../results/proofs")]
        dir: PathBuf,
    },
}

fn signing_keys(n: usize, seed: u8) -> Vec<SigningKey> {
    (0..n)
        .map(|i| {
            let mut s = [seed; 32];
            s[0] = i as u8;
            SigningKey::from_bytes(&s)
        })
        .collect()
}

const EPOCH: u64 = 7;
const CONFIG: [u8; 32] = [0xC0; 32];

fn checkpoint_input(n: usize, with_change: bool) -> CheckpointInput {
    checkpoint_input_at(n, with_change, EPOCH + 1)
}

fn checkpoint_input_at(n: usize, with_change: bool, change_epoch: u64) -> CheckpointInput {
    let t = |n: usize| -> u16 { ((2 * n).div_ceil(3)).min(n.saturating_sub(1)).max(1) as u16 };
    let old = signing_keys(n, 1);
    let old_pub: Vec<Key> = old.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let (keys, threshold, cur, change) = if with_change {
        // One key leaves and a new one joins, signed by the old set at its threshold.
        let mut new = signing_keys(n, 2);
        new.truncate(n);
        let new_pub: Vec<Key> = new.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let op = encode_config_op(&new_pub, t(n), change_epoch, 256);
        let digest: [u8; 32] = {
            use blake2::{digest::consts::U32, Blake2b, Digest};
            Blake2b::<U32>::digest(&op).into()
        };
        let sigs = (0..t(n) as usize)
            .map(|i| (i as u16, old[i].sign(&digest).to_bytes().to_vec()))
            .collect();
        (old_pub, t(n), new, Some(KeyChange { op_bytes: op, sigs }))
    } else {
        (old_pub, t(n), old, None)
    };
    let cur_pub: Vec<Key> = cur.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let cur_epoch = if with_change { change_epoch } else { EPOCH };
    let checkpoint = Checkpoint {
        config: CONFIG,
        channel_id: [0xAB; 32],
        block_id: 123_456,
        block_hash: [0x11; 32],
        burn_root: [0x22; 32],
    };
    let msg = checkpoint_message(&keyset_hash(&cur_pub, threshold, cur_epoch), &checkpoint);
    // Signers taken from the top of the list, to show any index set works.
    let sigs = (0..threshold as usize)
        .map(|j| {
            let i = n - 1 - j;
            (i as u16, cur[i].sign(&msg).to_bytes().to_vec())
        })
        .collect();
    CheckpointInput { keys, threshold, epoch: EPOCH, change, checkpoint, sigs }
}

fn release_input(depth: usize) -> ReleaseInput {
    ReleaseInput {
        config: CONFIG,
        token: [0x7E; 20],
        nullifier_secret: [7; 32],
        blinding: [9; 32],
        dest: [0x42; 20],
        fee: 1_000_000_000_000_000,
        denom: 3,
        index: 0x5_5555 & ((1u64 << depth.min(63)) - 1),
        path: (0..depth).map(|i| [i as u8; 32]).collect(),
    }
}

fn fallback_bytes(size: usize) -> Vec<u8> {
    use blake2::{digest::consts::U32, Blake2b, Digest};
    let payload: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
    let tx_hash: [u8; 32] = Blake2b::<U32>::digest(&payload).into();
    let key = SigningKey::from_bytes(&[5; 32]);
    let mut out = key.verifying_key().to_bytes().to_vec();
    out.extend_from_slice(&key.sign(&tx_hash).to_bytes());
    out.extend_from_slice(&payload);
    out
}

/// (elf, image id, env) for a named case.
fn case(name: &str) -> Result<(&'static [u8], [u32; 8], ExecutorEnv<'static>)> {
    let mut b = ExecutorEnv::builder();
    if let Ok(po2) = std::env::var("SEGMENT_PO2") {
        b.segment_limit_po2(po2.parse()?);
    }
    let (elf, id) = if let Some(rest) = name.strip_prefix("checkpoint") {
        let (n, change) = match rest.strip_suffix("-change") {
            Some(n) => (n, true),
            None => (rest, false),
        };
        b.write(&checkpoint_input(n.parse()?, change))?;
        (CHECKPOINT_ELF, CHECKPOINT_ID)
    } else if let Some(d) = name.strip_prefix("release") {
        b.stdin(std::io::Cursor::new(release_input(d.parse()?).to_bytes()));
        (RELEASE_ELF, RELEASE_ID)
    } else if let Some(sz) = name.strip_prefix("fallback") {
        let bytes = fallback_bytes(sz.parse::<usize>()? * 1024);
        b.stdin(std::io::Cursor::new(bytes));
        (FALLBACK_ELF, FALLBACK_ID)
    } else if let Some(d) = name.strip_prefix("poseidon") {
        b.write(&d.parse::<u32>()?)?;
        (POSEIDON_ELF, POSEIDON_ID)
    } else {
        anyhow::bail!("unknown case {name}");
    };
    Ok((elf, id, b.build()?))
}

/// Inputs the guests must refuse, one per bug fixed on 2026-11-18.
fn refusal_case(name: &str) -> Result<(&'static [u8], ExecutorEnv<'static>)> {
    let mut b = ExecutorEnv::builder();
    let elf = match name {
        "release32-index-above-depth" => {
            let mut input = release_input(32);
            input.index |= 1 << 32;
            b.stdin(std::io::Cursor::new(input.to_bytes()));
            RELEASE_ELF
        }
        "checkpoint4-duplicate-key" => {
            // Key 1 repeats key 2, so two holders would pass a threshold of three.
            let sk = signing_keys(4, 1);
            let mut keys: Vec<Key> = sk.iter().map(|k| k.verifying_key().to_bytes()).collect();
            keys[1] = keys[2];
            let checkpoint = Checkpoint {
                config: CONFIG,
                channel_id: [0xAB; 32],
                block_id: 123_456,
                block_hash: [0x11; 32],
                burn_root: [0x22; 32],
            };
            let msg = checkpoint_message(&keyset_hash(&keys, 3, EPOCH), &checkpoint);
            let sig = |i: usize| sk[i].sign(&msg).to_bytes().to_vec();
            let sigs = vec![(3, sig(3)), (2, sig(2)), (1, sig(2))];
            b.write(&CheckpointInput { keys, threshold: 3, epoch: EPOCH, change: None, checkpoint, sigs })?;
            CHECKPOINT_ELF
        }
        "checkpoint4-change-replayed" => {
            b.write(&checkpoint_input_at(4, true, EPOCH))?;
            CHECKPOINT_ELF
        }
        other => anyhow::bail!("unknown refusal case {other}"),
    };
    Ok((elf, b.build()?))
}

const REFUSAL_CASES: &[&str] =
    &["release32-index-above-depth", "checkpoint4-duplicate-key", "checkpoint4-change-replayed"];

const EXEC_CASES: &[&str] = &[
    "checkpoint3", "checkpoint4", "checkpoint5", "checkpoint7", "checkpoint10", "checkpoint16",
    "checkpoint3-change", "checkpoint7-change",
    "release20", "release32",
    "poseidon1", "poseidon20", "poseidon32",
    "fallback1", "fallback64", "fallback1024",
];

fn vm_hwm_kb() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Exec => {
            let mut rows = Vec::new();
            for name in EXEC_CASES {
                let (elf, _, env) = case(name)?;
                let t0 = Instant::now();
                let info = default_executor().execute(env, elf)?;
                let ms = t0.elapsed().as_millis();
                println!(
                    "{name:<22} user_cycles={:>12} ({:6.1}% of 10M) segments={:>3} exec={ms}ms",
                    info.cycles(),
                    info.cycles() as f64 / 1e5,
                    info.segments.len()
                );
                rows.push(serde_json::json!({
                    "case": name, "user_cycles": info.cycles(), "segments": info.segments.len(),
                    "segment_po2": info.segments.iter().map(|s| s.po2).collect::<Vec<_>>(),
                    "exec_ms": ms,
                }));
            }
            fs::write("../results/cycles.json", serde_json::to_string_pretty(&rows)?)?;
            let mut refusals = Vec::new();
            for name in REFUSAL_CASES {
                let (elf, env) = refusal_case(name)?;
                let err = match default_executor().execute(env, elf) {
                    Ok(_) => anyhow::bail!("{name}: the guest accepted an input it must refuse"),
                    Err(e) => format!("{e:#}"),
                };
                println!("{name:<30} refused: {}", err.lines().next().unwrap_or(""));
                refusals.push(serde_json::json!({ "case": name, "refused": true, "error": err }));
            }
            fs::write("../results/refusals.json", serde_json::to_string_pretty(&refusals)?)?;
        }
        Cmd::Prove { case: name, stage, dir } => {
            fs::create_dir_all(&dir)?;
            let path = |s: &str| dir.join(format!("{name}.{s}.bin"));
            let prover = default_prover();
            let t0 = Instant::now();
            let receipt: Receipt = match stage.as_str() {
                "composite" => {
                    let (elf, _, env) = case(&name)?;
                    let info = prover.prove_with_opts(env, elf, &ProverOpts::composite())?;
                    println!("segments={} user_cycles={}", info.stats.segments, info.stats.user_cycles);
                    info.receipt
                }
                "succinct" => {
                    let r: Receipt = bincode::deserialize(&fs::read(path("composite"))?)?;
                    prover.compress(&ProverOpts::succinct(), &r)?
                }
                "groth16" => {
                    let r: Receipt = bincode::deserialize(&fs::read(path("succinct"))?)?;
                    prover.compress(&ProverOpts::groth16(), &r)?
                }
                other => anyhow::bail!("unknown stage {other}"),
            };
            let secs = t0.elapsed().as_secs_f64();
            let (_, id, _) = case(&name)?;
            receipt.verify(id).context("receipt does not verify")?;
            let bytes = bincode::serialize(&receipt)?;
            fs::write(path(&stage), &bytes)?;
            let mut out = serde_json::json!({
                "case": name, "stage": stage, "seconds": secs, "receipt_bytes": bytes.len(),
                "vm_hwm_kb": vm_hwm_kb(),
                "threads": std::env::var("RAYON_NUM_THREADS").unwrap_or_default(),
            });
            if stage == "groth16" {
                let seal = receipt.inner.groth16()?.seal.clone();
                let image_id: risc0_zkvm::sha::Digest = id.into();
                out["seal"] = hex::encode(&seal).into();
                out["journal"] = hex::encode(&receipt.journal.bytes).into();
                out["image_id"] = hex::encode(image_id.as_bytes()).into();
            }
            println!("{}", serde_json::to_string(&out)?);
            fs::write(dir.join(format!("{name}.{stage}.json")), serde_json::to_string_pretty(&out)?)?;
        }
    }
    Ok(())
}
