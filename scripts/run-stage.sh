#!/usr/bin/env bash
# Usage: run-stage.sh <case> <stage>. Four cores, 8 GB, local prover, real proving.
set -euo pipefail
cd "$(dirname "$0")/../zk"
log=../results/logs/$1.$2.po2-${SEGMENT_PO2:-20}.log
export SEGMENT_PO2=${SEGMENT_PO2:-20}
RISC0_DEV_MODE=0 RISC0_PROVER=local RAYON_NUM_THREADS=4 \
  systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 \
  taskset -c 0-3 /usr/bin/time -v ./target/release/spike1 prove --case "$1" --stage "$2" >"$log" 2>&1
grep -E '^\{|Maximum resident|Elapsed \(wall' "$log"
