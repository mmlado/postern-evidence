// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";
import {Groth16Verifier as CircomVerifier32} from "../src/Verifier32.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        RiscZeroGroth16Verifier r0 = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        CircomVerifier32 c32 = new CircomVerifier32();
        vm.stopBroadcast();
        console.log("R0=%s", address(r0));
        console.log("C32=%s", address(c32));
    }
}
