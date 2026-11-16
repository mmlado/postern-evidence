#!/usr/bin/env bash
# Pinned to the risc0-ethereum commit the gas figures were measured against.
set -euo pipefail
cd "$(dirname "$0")/../gas"
mkdir -p lib
[ -d lib/risc0-ethereum ] || git clone https://github.com/risc0/risc0-ethereum lib/risc0-ethereum
git -C lib/risc0-ethereum checkout 365e7b2
git -C lib/risc0-ethereum submodule update --init lib/forge-std lib/openzeppelin-contracts
