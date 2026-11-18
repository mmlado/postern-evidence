"""Verify gas on a local anvil: RISC Zero Groth16 receipts and the Circom depth-32 proof.

Usage: python3 -I measure.py <R0 verifier address> <Circom verifier address> <private key>
Writes ../results/gas.json.
"""
import hashlib
import json
import os
import subprocess
import sys

D = os.path.dirname(os.path.abspath(__file__))
CAST = os.path.expanduser("~/.foundry/bin/cast")
RPC = "http://127.0.0.1:8545"
R0_SIG = "verify(bytes,bytes32,bytes32)"
C32_SIG = "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[5])"


def cast(*args, check=True):
    p = subprocess.run([CAST, *args], capture_output=True, text=True)
    if check and p.returncode:
        raise RuntimeError(f"cast {args[0]} failed: {p.stderr.strip()[:300]}")
    return p


def calldata_gas(hexdata):
    b = bytes.fromhex(hexdata.removeprefix("0x"))
    zero = b.count(0)
    nonzero = len(b) - zero
    return {"bytes": len(b), "standard": 4 * zero + 16 * nonzero, "eip7623_floor_tokens": zero + 4 * nonzero}


def measure(addr, sig, args, key):
    data = cast("calldata", sig, *args).stdout.strip()
    est = int(cast("estimate", "--rpc-url", RPC, addr, sig, *args).stdout.strip())
    # Fixed limit: the snarkjs verifier returns false on precompile OOG instead of reverting,
    # so a limit taken from eth_estimateGas measures a failed check.
    tx = json.loads(cast("send", "--json", "--gas-limit", "2000000", "--rpc-url", RPC,
                         "--private-key", key, addr, sig, *args).stdout)
    if int(tx["status"], 16) != 1:
        raise RuntimeError(f"tx {tx['transactionHash']} reverted")
    used = int(tx["gasUsed"], 16)
    cd = calldata_gas(data)
    return {"tx": tx["transactionHash"], "eth_estimateGas": est, "gas_used": used, "calldata": cd,
            "execution": used - 21000 - cd["standard"]}


def final_return(tx):
    lines = [l for l in cast("run", "--rpc-url", RPC, tx).stdout.splitlines() if "[Return]" in l]
    return lines[-1].split("[Return]")[-1].strip() if lines else ""


# Field layout of the committed struct: ("b", n) is a byte array (one u32 word per byte),
# ("w", n) is an integer of n words.
LAYOUT = {
    "release32": [("b", 32), ("b", 20), ("b", 32), ("b", 32), ("b", 20), ("w", 4), ("w", 1), ("w", 1)],
    "checkpoint7": [("b", 32), ("b", 32), ("b", 32), ("b", 32), ("w", 2), ("b", 32), ("b", 32)],
}


def journal_encoding(case, journal_hex):
    b = bytes.fromhex(journal_hex)
    packed, i = bytearray(), 0
    for kind, n in LAYOUT[case]:
        words = [b[i + 4 * k:i + 4 * k + 4] for k in range(n)]
        i += 4 * n
        if kind == "b":
            assert all(w[1:] == b"\0\0\0" for w in words)
            packed += bytes(w[0] for w in words)
        else:
            packed += b"".join(words)
    assert i == len(b)
    sha = lambda n: 60 + 12 * ((n + 31) // 32)
    return {
        "as_committed": {**calldata_gas(b.hex()), "sha256_precompile": sha(len(b))},
        "packed": {**calldata_gas(packed.hex()), "sha256_precompile": sha(len(packed))},
    }


def main(r0, c32, key):
    out = {"anvil": cast("rpc", "--rpc-url", RPC, "anvil_nodeInfo").stdout.strip()}
    selector = cast("call", "--rpc-url", RPC, r0, "SELECTOR()(bytes4)").stdout.strip()
    out["r0_selector"] = selector
    for case in ("release32", "checkpoint7"):
        p = json.load(open(os.path.join(D, "..", "results", "proofs", f"{case}.groth16.json")))
        seal = selector + p["seal"]
        image_id = "0x" + p["image_id"]
        digest = "0x" + hashlib.sha256(bytes.fromhex(p["journal"])).hexdigest()
        args = [seal, image_id, digest]
        cast("call", "--rpc-url", RPC, r0, R0_SIG, *args)
        bad = "0x" + hashlib.sha256(bytes.fromhex(p["journal"]) + b"\0").hexdigest()
        rejects = cast("call", "--rpc-url", RPC, r0, R0_SIG, seal, image_id, bad, check=False).returncode != 0
        out[case] = {**measure(r0, R0_SIG, args, key), "rejects_wrong_journal": rejects,
                     "journal": journal_encoding(case, p["journal"])}

    build = os.path.join(D, "..", "circom", "build")
    pr = json.load(open(os.path.join(build, "proof32.json")))
    pub = json.load(open(os.path.join(build, "public32.json")))
    a = f"[{pr['pi_a'][0]},{pr['pi_a'][1]}]"
    # Solidity expects each G2 coordinate as (imaginary, real), the reverse of snarkjs JSON.
    b = f"[[{pr['pi_b'][0][1]},{pr['pi_b'][0][0]}],[{pr['pi_b'][1][1]},{pr['pi_b'][1][0]}]]"
    c = f"[{pr['pi_c'][0]},{pr['pi_c'][1]}]"
    s = "[" + ",".join(pub) + "]"
    ok = cast("call", "--rpc-url", RPC, c32, C32_SIG + "(bool)", a, b, c, s).stdout.strip()
    bad_pub = "[" + ",".join(pub[:-1] + [str(int(pub[-1]) + 1)]) + "]"
    bad = cast("call", "--rpc-url", RPC, c32, C32_SIG + "(bool)", a, b, c, bad_pub).stdout.strip()
    m = measure(c32, C32_SIG, [a, b, c, s], key)
    out["circom_release32"] = {**m, "tx_returns": final_return(m["tx"]),
                               "valid_returns": ok, "wrong_public_returns": bad}

    json.dump(out, open(os.path.join(D, "..", "results", "gas.json"), "w"), indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main(*sys.argv[1:4])
