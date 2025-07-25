// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IEmissary } from "src/interfaces/IEmissary.sol";

contract AlwaysRevertingEmissary is IEmissary {
    error AlwaysReverting();

    function verifyClaim(
        address, /* sponsor */
        bytes32, /* digest */
        bytes32, /* claimHash */
        bytes calldata, /* signature */
        bytes12 /* lockTag */
    ) external pure override returns (bytes4) {
        revert AlwaysReverting();
    }
}
