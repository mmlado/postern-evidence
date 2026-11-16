pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mux1.circom";

// Burn leaf in a Poseidon tree, nullifier from the secret and the leaf index.
template Release(depth) {
    signal output root;
    signal output nullifier;
    signal input dest;
    signal input fee;
    signal input denom;

    signal input nullifierSecret;
    signal input blinding;
    signal input index;
    signal input path[depth];

    component leaf = Poseidon(5);
    leaf.inputs[0] <== nullifierSecret;
    leaf.inputs[1] <== blinding;
    leaf.inputs[2] <== dest;
    leaf.inputs[3] <== fee;
    leaf.inputs[4] <== denom;

    component nul = Poseidon(2);
    nul.inputs[0] <== nullifierSecret;
    nul.inputs[1] <== index;
    nullifier <== nul.out;

    component bits = Num2Bits(depth);
    bits.in <== index;

    component left[depth];
    component right[depth];
    component h[depth];
    signal cur[depth + 1];
    cur[0] <== leaf.out;
    for (var i = 0; i < depth; i++) {
        left[i] = Mux1();
        left[i].c[0] <== cur[i];
        left[i].c[1] <== path[i];
        left[i].s <== bits.out[i];
        right[i] = Mux1();
        right[i].c[0] <== path[i];
        right[i].c[1] <== cur[i];
        right[i].s <== bits.out[i];
        h[i] = Poseidon(2);
        h[i].inputs[0] <== left[i].out;
        h[i].inputs[1] <== right[i].out;
        cur[i + 1] <== h[i].out;
    }
    root <== cur[depth];
}
