// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITheCompactCore } from "./ITheCompactCore.sol";

interface ITheCompactMultiChain {

    struct EnhancedCompact {
        uint256 chainId;
        ITheCompactCore.Compact compact;
    }

    struct EnhancedClaim {
        EnhancedCompact[] compacts; // The compact to claim from.
        string typeString; // The full type string of the claim, including potential witness data
        bytes32 witness; // Hash of the witness data.
        bytes allocatorSignature; // Authorization from the allocator.
        bytes sponsorSignature; // Authorization from the sponsor.
    }

    // @notice Register a Compact to skip the sponsors signature at claim time
    // @dev Can only be called by the sponsor
    function multiChainRegister(EnhancedCompact[] calldata compacts) external;

    // @notice Deposit and register a multi chain compact
    // @dev The sponsor must not be the msg.sender, but the msg.sender must provide the tokens of the issuing chain id for the registered claim
    function multiChainDepositAndRegister(EnhancedCompact[] calldata compacts, bytes32 witness, string calldata typeString) external payable;

    // @notice Claims tokens from the compact of a multi chain claim
    // @dev This will only claim the tokens of issued on the relevant chain id
    // @dev Only the arbiter can call this function
    // @dev The first bit of the bytes32 recipient MUST be set to 1 by the arbiter, if the recipient was unknown to the sponsor
    //      and the arbiter was made responsible for setting the recipient.
    //      If the first bit is not set, the recipient was known to the sponsor / allocator and included in the signed data. 
    // @dev If the arbiter wants to split the claim even more, they may claim the tokens themselves and distribute them at will.
    function multiChainClaim(EnhancedClaim[] calldata claims, bool withdraw) external returns (bool);
}
