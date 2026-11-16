pragma circom 2.1.6;
include "circomlib/circuits/sha256/sha256.circom";
// One SHA-256 tree node (64-byte input) and one 136-byte leaf, for constraint counts only.
template Pair() {
    signal input a[512];
    signal input b[1088];
    signal output x[256];
    signal output y[256];
    component n = Sha256(512);
    component l = Sha256(1088);
    n.in <== a;
    l.in <== b;
    x <== n.out;
    y <== l.out;
}
component main = Pair();
