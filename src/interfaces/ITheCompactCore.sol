// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Scope } from "../types/Scope.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";

interface ITheCompactCore {

    struct Compact {
        uint256 chainId; // The chain Id of the allocated tokens
        address arbiter; // The account tasked with verifying and submitting the claim.
        address sponsor; // The account to source the tokens from.
        uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires; // The time at which the claim expires.
        Allocation[] inputs; // The inputs to the claim.
            // Optional witness may follow.
    }

    struct Claim {
        Compact compact; // The compact to claim from.
        string typeString; // The full type string of the claim, including potential witness data
        bytes32 witness; // Hash of the witness data.
        bytes allocatorSignature; // Authorization from the allocator.
        bytes sponsorSignature; // Authorization from the sponsor.
    }

    struct Allocation {
		uint256 id; // The token ID of the ERC6909 token to allocate.
		uint256 amount; // The amount of ERC6909 tokens to allocate.
        bytes32 recipient; // The address to receive the tokens. 
        // NOTE: For claims, leave recipient empty if fillers are unknown. Must be a 160 bit address.
        //       Can be used to ensure known entities receive their share of the claim
    }

    struct Transfer {
        uint256 nonce;
        uint256 expires;
        Allocation[] recipients;
    }

    struct DelegatedTransfer {
        address from;
        Transfer transfer;
    }

    enum ForcedWithdrawalStatus {
        Disabled, // Not pending or enabled for forced withdrawal
        Pending, // Not yet available, but initiated
        Enabled // Available for forced withdrawal on demand
    }

    // @notice Deposit native tokens into the compact
    // @dev can be used for a delegated deposit by setting a recipient
    function deposit(address allocator, Scope scope, ResetPeriod resetPeriod, address recipient) external payable returns (uint256 id);

    // @notice Deposit ERC20 tokens into the compact
    // @dev can be used for a delegated deposit by setting a recipient
    function deposit(address token, uint256 amount, address allocator, ResetPeriod resetPeriod, Scope scope, address recipient) external returns (uint256 id);

    // @notice Register a Compact to skip the sponsors signature at claim time
    // @dev Does not require a sponsor signature if the msg.sender is the sponsor
    /// TODO: Figure out away to have a delegated register without the ability to maliciously set a claim for someone else without a sponsor signature
    function register(Compact calldata compact) external;

    // @notice Register a Compact with a witness to skip the sponsors signature at claim time
    // @dev Does not require a sponsor signature if the msg.sender is the sponsor
    /// TODO: Figure out away to have a delegated register without the ability to maliciously set a claim for someone else without a sponsor signature
    function registerWithWitness(Compact calldata compact, bytes32 witness, string calldata typeString) external;

    // @notice Overrides 6909 transfer function
    // @dev Expects an on chain allocator
    function transfer(address to, uint256 id, uint256 amount) external returns (bool);

    // @notice Overrides 6909 transfer function
    // @dev Expects an on chain allocator
    // @dev Requires an approval from the sender
    function transferFrom(address from, address to, uint256 id, uint256 amount) external returns (bool);

    // @notice Flexible transfer of tokens
    // @dev Server based allocators must use this function for transfers
    function allocatedTransfer(Transfer calldata transfer) external returns (bool);

    // @notice Flexible transfer of tokens 
    // @dev Requires an approval from the sender
    function allocatedTransferFrom(DelegatedTransfer calldata transfer, bytes calldata sponsorSignature) external returns (bool);

    // @notice Flexible withdrawal of tokens
    // @dev Works for server based allocators and on chain allocators
    function withdrawal(Transfer calldata transfer) external returns (bool);

    // @notice Flexible withdrawal of tokens delegated by a sponsor
    // @dev Works for server based allocators and on chain allocators
    // @dev Requires an approval from the sender
    function withdrawalFrom(DelegatedTransfer calldata transfer, bytes calldata sponsorSignature) external returns (bool);

    // @notice Overrides 6909 setOperator function
    // @notice Sets whether an operator is approved to manage the tokens of the caller
    function setOperator(address operator, bool approved) external returns (bool);

    // @notice Overrides 6909 approve function
    // @notice Approves a spender to spend tokens on behalf of the caller
    function approve(address spender, uint256 id, uint256 amount) external returns (bool);

    // @notice Approves a spender to spend tokens on behalf of the caller
    // @dev Approves a spender by a signature of the sponsor
    function approveBySignature(address spender, uint256 id, uint256 amount, uint32 expires, bytes calldata signature) external returns (bool);

    // @notice Claims tokens from the compact
    // @dev Only the arbiter can call this function
    // @dev The first bit of the bytes32 recipient MUST be set to 1 by the arbiter, if the recipient was unknown to the sponsor
    //      and the arbiter was made responsible for setting the recipient.
    //      If the first bit is not set, the recipient was known to the sponsor / allocator and included in the signed data. 
    // @dev If the arbiter wants to split the claim even more, they may claim the tokens themselves and distribute them at will.
    function claim(Claim calldata claim, bool withdraw) external returns (bool);

    // @notice Enables a forced withdrawal for a resource lock
    // @dev Blocks new deposits for the resource lock
    function enableForcedWithdrawal(uint256[] calldata ids) external returns (uint256 withdrawableAt);

    // @notice Disables a forced withdrawal for a resource lock
    // @dev Unblocks new deposits for the resource lock
    function disableForcedWithdrawal(uint256[] calldata ids) external returns (bool);

    // @notice Executes a forced withdrawal from a resource lock after the reset period has elapsed
    // @dev Will withdraw all of the sponsors tokens from the resource lock
    function forcedWithdrawal(uint256[] calldata ids, address recipient) external returns (bool);

    // @notice Consumes a set of nonces
    // @dev Only callable by a registered allocator
    function consume(uint256[] calldata nonces) external returns (bool);

    // @notice Registers an allocator
    // @dev Can be called by anyone if one of three conditions is met: the caller is the allocator address being registered, 
    //      the allocator address contains code, or a proof is supplied representing valid create2 deployment parameters that resolve to the supplied allocator address.
    function __registerAllocator(address allocator, bytes calldata proof) external returns (uint96 allocatorId);

    // @notice Retrieves the fees for a claim
    // @dev Allocators or an Arbiter may require a fee to be paid in order to process a claim
    // @dev The fees must be included in the Compacts inputs if the allocator or arbiter require a fee
    function getClaimFee(uint256[2][] calldata idAndAmount, bool allocator, bool arbiter) external view returns (uint256 allocatorFee, uint256 arbiterFee);

    // @notice Checks the forced withdrawal status of a resource lock for a given account
    // @dev Returns both the current status (disabled, pending, or enabled) and the timestamp at which forced withdrawals will be enabled
    //      (if status is pending) or became enabled (if status is enabled).
    function getForcedWithdrawalStatus(address account, uint256 id) external view returns (ForcedWithdrawalStatus status, uint256 availableAt);

    // @notice Checks whether a specific nonce has been consumed by an allocator
    // @dev Once consumed, a nonce cannot be reused for claims mediated by that allocator
    function hasConsumedAllocatorNonce(uint256 nonce, address allocator) external view returns (bool consumed);

    // @notice Returns the domain separator of the contract
    function DOMAIN_SEPARATOR() external view returns (bytes32 domainSeparator);

    // @notice Returns the name of the contract
    function name() external pure returns (string memory);

}