// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITheCompact } from "./interfaces/ITheCompact.sol";

import { BatchTransfer, SplitBatchTransfer } from "./types/BatchClaims.sol";
import { BasicTransfer, SplitTransfer } from "./types/Claims.sol";
import { CompactCategory } from "./types/CompactCategory.sol";
import { Lock } from "./types/Lock.sol";
import { Scope } from "./types/Scope.sol";
import { ResetPeriod } from "./types/ResetPeriod.sol";
import { ForcedWithdrawalStatus } from "./types/ForcedWithdrawalStatus.sol";

import { TheCompactLogic } from "./lib/TheCompactLogic.sol";

import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

/**
 * @title The Compact
 * @custom:version 0 (early-stage proof-of-concept)
 * @author 0age (0age.eth)
 * @notice The Compact is an ownerless ERC6909 contract that facilitates the voluntary
 *         formation and mediation of reusable "resource locks."
 *         This contract has not yet been properly tested, audited, or reviewed.
 */
contract TheCompact is ITheCompact, ERC6909, TheCompactLogic {
    // NOTIFY READERS OF THE NATSPEC FOR THE FUNCTIONS IN THE INTERFACE
    function deposit(address allocator) external payable returns (uint256) {
        // COMPLETED PR
        return _performBasicNativeTokenDeposit(allocator); // DirectDepositLogic.sol
    }

    // THE CLAIM REGISTERED IS NOT A SECRET IN THIS CASE, SO COULD WE VERIFY THE CLAIMHASH?
    function depositAndRegister(address allocator, bytes32 claimHash, bytes32 typehash) external payable returns (uint256 id) {
        // COMPLETED PR
        id = _performBasicNativeTokenDeposit(allocator); // DirectDepositLogic.sol

        _registerWithDefaults(claimHash, typehash); // RegistrationLogic.sol
    }

    // COULD ALSO BE USED FOR NATIVE TOKENS TO REDUCE NUMBER OF FUNCTIONS - 'AMOUNT' COULD BE USED TO VERIFY THE INTENDED AMOUNT OF NATIVE TOKENS TO BE DEPOSITED
    function deposit(address token, address allocator, uint256 amount) external returns (uint256) {
        // Completed PR
        return _performBasicERC20Deposit(token, allocator, amount); // DirectDepositLogic.sol
    }

    // THE CLAIM REGISTERED IS NOT A SECRET IN THIS CASE, SO COULD WE VERIFY THE CLAIMHASH?
    function depositAndRegister(address token, address allocator, uint256 amount, bytes32 claimHash, bytes32 typehash) external returns (uint256 id) {
        // Completed PR
        id = _performBasicERC20Deposit(token, allocator, amount); // DirectDepositLogic.sol

        _registerWithDefaults(claimHash, typehash); // RegistrationLogic.sol
    }

    // HAVING THE RECIPIENT AS A PARAMETER ALLOWS US TO OUTSOURCE depositAndRegister FUNCTIONS TO HELPER CONTRACTS
    // IF WE USE A CALLBACK FOR THE USER TO SEND IN THE TOKENS (LIKE IN UNISWAP V3), WE SAVE ON GAS BY SKIPPING APPROVAL FOR THIS CONTRACT.
    // THE CONTRACT FEELS A LITTLE LIKE UNISWAP V3 CORE AND PERIPHERY CONTRACTS WERE COMBINED IN ONE. COULD BE INTERESTING TO EXPLORE
    // WHERE TO SEPERATE THE LOGIC TO KEEP IT EASY TO READ AND MODULAR AT THE SAME TIME.
    function deposit(address allocator, ResetPeriod resetPeriod, Scope scope, address recipient) external payable returns (uint256) {
        // Completed PR
        // COULD ELIMINATE A LOT OF THE FUNCTIONS IN THE DEPOSIT CONTRACTS BY HANDELING DEFAULT PARAMETERS IN THIS CONTRACT. COULD INCREASE READABILITY.
        return _performCustomNativeTokenDeposit(allocator, resetPeriod, scope, recipient); // DirectDepositLogic.sol
    }

    function deposit(address token, address allocator, ResetPeriod resetPeriod, Scope scope, uint256 amount, address recipient) external returns (uint256) {
        // Completed PR
        // COULD ELIMINATE A LOT OF THE FUNCTIONS IN THE DEPOSIT CONTRACTS BY HANDELING DEFAULT PARAMETERS IN THIS CONTRACT. COULD INCREASE READABILITY.
        return _performCustomERC20Deposit(token, allocator, resetPeriod, scope, amount, recipient); // DirectDepositLogic.sol
    }

    // IN HERE, WE ARE ACTUALLY COMBINING NATIVE AND ERC20 TOKENS IN THE SAME FUNCTION, WE CAN DO THE SAME ABOVE.
    function deposit(uint256[2][] calldata idsAndAmounts, address recipient) external payable returns (bool) { 
        // Completed PR
        _processBatchDeposit(idsAndAmounts, recipient); // DirectDepositLogic.sol

        return true;
    }

    function depositAndRegister(uint256[2][] calldata idsAndAmounts, bytes32[2][] calldata claimHashesAndTypehashes, uint256 duration) external payable returns (bool) {
        _processBatchDeposit(idsAndAmounts, msg.sender);

        return _registerBatch(claimHashesAndTypehashes, duration); // NEED TO LOOK INTO THIS
    }

    function deposit( // RENAME TO depositViaPermit2 FOR CLEAR SEPARATION?
        address token,
        uint256, // amount
        uint256, // nonce
        uint256, // deadline
        address, // depositor
        address, // allocator
        ResetPeriod, // resetPeriod
        Scope, //scope
        address recipient,
        bytes calldata signature
    ) external returns (uint256) { // Completed PR
        return _depositViaPermit2(token, recipient, signature); // DepositViaPermit2Logic.sol
    }

    // ITS HARD TO FOLLOW A PATTERN HERE... DEPOSIT AND REGISTER VIA PERMIT2 HAS SUCH A DIFFERENT INTERNAL PROCESS COMPARED TO ONLY DEPOSITING (NOT JUST THE REGISTERING PART ADDED).
    function depositAndRegister( // RENAME TO depositAndRegisterViaPermit2 FOR CLEAR SEPARATION?
        address token,
        uint256, // amount
        uint256, // nonce
        uint256, // deadline
        address depositor, // also recipient
        address, // allocator
        ResetPeriod resetPeriod,
        Scope, //scope
        bytes32 claimHash,
        CompactCategory compactCategory,
        string calldata witness,
        bytes calldata signature
    ) external returns (uint256) {
        return _depositAndRegisterViaPermit2(token, depositor, resetPeriod, claimHash, compactCategory, witness, signature);
    }

    function deposit(
        address, // depositor
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        uint256, // nonce
        uint256, // deadline
        address, // allocator
        ResetPeriod, // resetPeriod
        Scope, //scope
        address recipient,
        bytes calldata signature
    ) external payable returns (uint256[] memory) {
        return _depositBatchViaPermit2(permitted, recipient, signature);
    }

    function depositAndRegister(
        address depositor,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        uint256, // nonce
        uint256, // deadline
        address, // allocator
        ResetPeriod resetPeriod,
        Scope, //scope
        bytes32 claimHash,
        CompactCategory compactCategory,
        string calldata witness,
        bytes calldata signature
    ) external payable returns (uint256[] memory) {
        return _depositBatchAndRegisterViaPermit2(depositor, permitted, resetPeriod, claimHash, compactCategory, witness, signature);
    }

    function allocatedTransfer(BasicTransfer calldata transfer) external returns (bool) {
        return _processBasicTransfer(transfer, _release);
    }

    function allocatedWithdrawal(BasicTransfer calldata withdrawal) external returns (bool) {
        return _processBasicTransfer(withdrawal, _withdraw);
    }

    function allocatedTransfer(SplitTransfer calldata transfer) external returns (bool) {
        return _processSplitTransfer(transfer, _release);
    }

    function allocatedWithdrawal(SplitTransfer calldata withdrawal) external returns (bool) {
        return _processSplitTransfer(withdrawal, _withdraw);
    }

    function allocatedTransfer(BatchTransfer calldata transfer) external returns (bool) {
        return _processBatchTransfer(transfer, _release);
    }

    function allocatedWithdrawal(BatchTransfer calldata withdrawal) external returns (bool) {
        return _processBatchTransfer(withdrawal, _withdraw);
    }

    function allocatedTransfer(SplitBatchTransfer calldata transfer) external returns (bool) {
        return _processSplitBatchTransfer(transfer, _release);
    }

    function allocatedWithdrawal(SplitBatchTransfer calldata withdrawal) external returns (bool) {
        return _processSplitBatchTransfer(withdrawal, _withdraw);
    }

    function enableForcedWithdrawal(uint256 id) external returns (uint256) {
        return _enableForcedWithdrawal(id);
    }

    function disableForcedWithdrawal(uint256 id) external returns (bool) {
        return _disableForcedWithdrawal(id);
    }

    function forcedWithdrawal(uint256 id, address recipient, uint256 amount) external returns (bool) {
        return _processForcedWithdrawal(id, recipient, amount);
    }

    function register(bytes32 claimHash, bytes32 typehash, uint256 duration) external returns (bool) {
        _register(msg.sender, claimHash, typehash, duration);
        return true;
    }

    function getRegistrationStatus(address sponsor, bytes32 claimHash, bytes32 typehash) external view returns (bool isActive, uint256 expires) {
        expires = _getRegistrationStatus(sponsor, claimHash, typehash);
        isActive = expires > block.timestamp;
    }

    function register(bytes32[2][] calldata claimHashesAndTypehashes, uint256 duration) external returns (bool) {
        return _registerBatch(claimHashesAndTypehashes, duration);
    }

    function consume(uint256[] calldata nonces) external returns (bool) {
        return _consume(nonces);
    }

    function __registerAllocator(address allocator, bytes calldata proof) external returns (uint96) {
        return _registerAllocator(allocator, proof);
    }

    function getForcedWithdrawalStatus(address account, uint256 id) external view returns (ForcedWithdrawalStatus, uint256) {
        return _getForcedWithdrawalStatus(account, id);
    }

    function getLockDetails(uint256 id) external view returns (address, address, ResetPeriod, Scope) {
        return _getLockDetails(id);
    }

    function hasConsumedAllocatorNonce(uint256 nonce, address allocator) external view returns (bool) {
        return _hasConsumedAllocatorNonce(nonce, allocator);
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /// @dev Returns the symbol for token `id`.
    function name(uint256 id) public view virtual override returns (string memory) {
        return _name(id);
    }

    /// @dev Returns the symbol for token `id`.
    function symbol(uint256 id) public view virtual override returns (string memory) {
        return _symbol(id);
    }

    /// @dev Returns the Uniform Resource Identifier (URI) for token `id`.
    function tokenURI(uint256 id) public view virtual override returns (string memory) {
        return _tokenURI(id);
    }

    /// @dev Returns the name for the contract.
    function name() external pure returns (string memory) {
        // Return the name of the contract.
        assembly ("memory-safe") {
            mstore(0x20, 0x20)
            mstore(0x4b, 0x0b54686520436f6d70616374)
            return(0x20, 0x60)
        }
    }

    function _beforeTokenTransfer(address from, address to, uint256 id, uint256 amount) internal virtual override {
        _ensureAttested(from, to, id, amount);
    }
}
