pragma circom 2.1.6;
include "release_poseidon.circom";
component main {public [dest, fee, denom]} = Release(32);
