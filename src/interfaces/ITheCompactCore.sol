// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Scope } from "../types/Scope.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";

interface ITheCompactCore {

    struct Compact {
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

    struct TokenTransfer {
        uint256 nonce;
        uint256 expires;
        Allocation[] recipients;
    }

    struct DelegatedTransfer {
        address from;
        TokenTransfer transfer;
    }

    // @notice Deposit native tokens into the compact
    // @dev can be used for a delegated deposit by setting a recipient
    function deposit(address allocator, Scope scope, ResetPeriod resetPeriod, address recipient) external payable returns (uint256 id);

    // @notice Deposit ERC20 tokens into the compact
    // @dev can be used for a delegated deposit by setting a recipient
    function deposit(address token, uint256 amount, address allocator, ResetPeriod resetPeriod, Scope scope, address recipient) external returns (uint256 id);

    // @notice Register a Compact to skip the sponsors signature at claim time
    // @dev Can only be called by the sponsor
    function register(Compact calldata compact) external;

    // @notice Register a Compact with a witness to skip the sponsors signature at claim time
    // @dev Can only be called by the sponsor
    function registerWithWitness(Compact calldata compact, bytes32 witness, string calldata typeString) external;

    // @notice Deposit and register a compact
    // @dev The sponsor must not be the msg.sender, but the msg.sender must provide the tokens for the registered claim
    function depositAndRegister(Compact calldata compact, bytes32 witness, string calldata typeString) external payable;

    // @notice Overrides 6909 setOperator function
    // @notice Sets whether an operator is approved to manage the tokens of the caller
    function setOperator(address operator, bool approved) external payable returns (bool);

    // @notice Overrides 6909 approve function
    // @notice Approves a spender to spend tokens on behalf of the caller
    function approve(address spender, uint256 id, uint256 amount) external payable returns (bool);

    // @notice Approves a spender to spend tokens on behalf of the caller
    // @dev Approves a spender by a signature of the sponsor
    function permit(address owner, address spender, uint256 id, uint256 value, uint256 deadline, bytes calldata signature) external returns (bool);

    // @notice Approves a spender to spend tokens on behalf of the caller
    // @dev The approval is only valid for the current transaction. The nonce will only be burned if the approval is used.
    //      If it is not used, the nonce will not be burned.
    // function transientPermit(address owner, address spender, uint256 id, uint256 value, uint32 deadline, bytes calldata signature) external returns (bool);

    // @notice Overrides 6909 transfer function
    // @dev Expects an on chain allocator
    function transfer(address to, uint256 id, uint256 amount) external payable returns (bool);

    // @notice Overrides 6909 transfer function
    // @dev Expects an on chain allocator
    // @dev Requires an approval from the sender
    function transferFrom(address from, address to, uint256 id, uint256 amount) external payable returns (bool);

    // @notice Flexible transfer of tokens
    // @dev Server based allocators must use this function for transfers
    // @dev For on chain allocators, the provided allocatorSignature should be an empty bytes
    // @dev For on chain allocators, the provided nonce should be 0
    function allocatedTransfer(TokenTransfer calldata transfer, bytes calldata allocatorSignature) external returns (bool);

    // @notice Flexible transfer of tokens by an operator
    // @dev Follows the same rules as 'allocatedTransfer'
    // @dev Requires an approval from the sender
    function allocatedTransferFrom(DelegatedTransfer calldata transfer, bytes calldata sponsorSignature) external returns (bool);

    // @notice Flexible withdrawal of tokens
    // @dev Works for server based allocators and on chain allocators
    // @dev For on chain allocators, the provided allocatorSignature should be an empty bytes
    // @dev For on chain allocators, the provided nonce should be 0
    function withdrawal(TokenTransfer calldata transfer, bytes calldata allocatorSignature) external returns (bool);

    // @notice Flexible withdrawal of tokens by an operator
    // @dev Follows the same rules as 'withdrawal'
    // @dev Requires an approval from the sender
    function withdrawalFrom(DelegatedTransfer calldata transfer, bytes calldata sponsorSignature) external returns (bool);

    // @notice Claims tokens from the compact
    // @dev Only the arbiter can call this function
    // @dev The first bit of the bytes32 recipient MUST be set to 1 by the arbiter, if the recipient was unknown to the sponsor
    //      and the arbiter was made responsible for setting the recipient.
    //      If the first bit is not set, the recipient was known to the sponsor / allocator and included in the signed data. 
    // @dev If the arbiter wants to split the claim even more, they may claim the tokens themselves and distribute them at will.
    function claim(Claim calldata claim, bool withdraw) external returns (bool);

    // @notice Claims tokens with a qualification exclusively signed by the allocator
    function claimWithQualification(Claim calldata claim, bytes32 qualificationHash, string calldata qualificationTypeString, bool withdraw) external returns (bool);

    // @notice Enables a forced withdrawal for a resource lock
    // @dev Blocks new deposits for the resource lock
    function enableForcedWithdrawal(uint256[] calldata ids) external returns (uint256[] memory withdrawableAt);

    // @notice Disables a forced withdrawal for a resource lock
    // @dev Unblocks new deposits for the resource lock
    function disableForcedWithdrawal(uint256[] calldata ids) external returns (uint256[] memory withdrawableAt);

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
    // @dev Allocators, an Arbiter, or another involved Service may require a guaranteed fee to be signed for in order to process a claim
    // @dev The remaining amount must replace the original amount in the Compacts inputs
    // @dev The fee must be included in the Compacts inputs with the provider as the recipient
    function getClaimFee(address[] calldata providers, uint256 id, uint256 amount) external view returns (uint256[] memory, uint256 remainingAmount);

    // @notice Checks the forced withdrawal status of a resource lock for a given account
    // @dev Returns both the current status (disabled, pending, or enabled) and the timestamp at which forced withdrawals will be enabled
    //      (if status is pending) or became enabled (if status is enabled).
    function getForcedWithdrawalStatus(address account, uint256 id) external view returns (uint256 availableAt);

    // @notice Checks whether a specific nonce has been consumed by an allocator
    // @dev Once consumed, a nonce cannot be reused for claims mediated by that allocator
    function hasConsumedAllocatorNonce(uint256 nonce, address allocator) external view returns (bool consumed);

    // @notice Retrieves the current nonce for a permit approval
    function getPermitNonce(address owner) external view returns (uint256);

    // @notice Returns the domain separator of the contract
    function DOMAIN_SEPARATOR() external view returns (bytes32 domainSeparator);

    // @notice Returns the name of the contract
    function name() external pure returns (string memory);

    // @notice Returns the version of the contract
    function version() external pure returns (string memory);

}