// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console } from "forge-std/Test.sol";

import { IdLib } from "../../src/lib/IdLib.sol";

contract IdLibTest is Test {
    function test_toCompactFlag() public pure {
        address testAddress = 0x000000000044449b4B19c2B8477Dbc403Cc4DA4e;
        uint8 compactFlag = IdLib.toCompactFlag(testAddress);
        assertEq(compactFlag, (10 - 3));
    }
}
