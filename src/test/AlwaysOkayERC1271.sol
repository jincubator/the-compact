// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IERC1271 } from "lib/permit2/src/interfaces/IERC1271.sol";

contract AlwaysOkayERC1271 is IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) public view override returns (bytes4) {
        return 0x1626ba7e;
    }
}
