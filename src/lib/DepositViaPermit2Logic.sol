// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { CompactCategory } from "../types/CompactCategory.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Scope } from "../types/Scope.sol";

import { DepositLogic } from "./DepositLogic.sol";
import { DepositViaPermit2Lib } from "./DepositViaPermit2Lib.sol";
import { RegistrationLib } from "./RegistrationLib.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { IdLib } from "./IdLib.sol";
import { ValidityLib } from "./ValidityLib.sol";

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

/**
 * @title DepositViaPermit2Logic
 * @notice Inherited contract implementing internal functions with logic for processing
 * token deposits via permit2. These deposits leverage Permit2 witness data to either
 * indicate the parameters of the lock to deposit into and the recipient of the deposit,
 * or the parameters of the compact to register alongside the deposit. Deposits can also
 * involve a single ERC20 token or a batch of tokens in a single Permit2 authorization.
 * @dev IMPORTANT NOTE: this logic operates directly on unallocated memory, and reads
 * directly from fixed calldata offsets; proceed with EXTREME caution when making any
 * modifications to either this logic contract (including the insertion of new logic) or
 * to the associated permit2 deposit function interfaces!
 */
contract DepositViaPermit2Logic is DepositLogic {
    using DepositViaPermit2Lib for bytes32;
    using DepositViaPermit2Lib for uint256;
    using IdLib for uint256;
    using IdLib for address;
    using IdLib for ResetPeriod;
    using EfficiencyLib for bool;
    using EfficiencyLib for uint256;
    using RegistrationLib for address;
    using ValidityLib for address;
    using SafeTransferLib for address;

    // Selector for the single token `permit2.permitWitnessTransferFrom` function.
    uint32 private constant _PERMIT_WITNESS_TRANSFER_FROM_SELECTOR = 0x137c29fe;

    // Address of the Permit2 contract.
    address private constant _PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /**
     * @notice Internal function for depositing ERC20 tokens using Permit2 authorization. The
     * depositor must approve Permit2 to transfer the tokens on its behalf unless the token in
     * question automatically grants approval to Permit2. The ERC6909 token amount received
     * by the recipient is derived from the difference between the starting and ending balance held
     * in the resource lock, which may differ from the amount transferred depending on the
     * implementation details of the respective token. The Permit2 authorization signed by the
     * depositor must contain a CompactDeposit witness containing the allocator, the reset period,
     * the scope, and the intended recipient of the deposit.
     * @param token       The address of the ERC20 token to deposit.
     * @param recipient   The address that will receive the corresponding the ERC6909 tokens.
     * @param signature   The Permit2 signature from the depositor authorizing the deposit.
     * @return            The ERC6909 token identifier of the associated resource lock.
     */
    function _depositViaPermit2(address token, address recipient, bytes calldata signature) internal returns (uint256) {
        // Derive the CompactDeposit witness hash.
        bytes32 witness = uint256(0xa4).asStubborn().deriveCompactDepositWitnessHash(); // witness data has an offest of 164 bytes in the calldata
        // Memory is now set up as follows:
        // -> memory pointer offset
        // [ 32 bytes ][ 32 bytes  ][   32 bytes  ][ 32 bytes ][ 32 bytes  ] <- memory content
        // [  PDWFH   ][ allocator ][ resetPeriod ][ scope    ][ recipient ]
        // [ 0 bytes  ][ 32 bytes  ][   64 bytes  ][ 96 bytes ][ 128 bytes ] <- memory offset

        // Note: Do NOT modify the memory from this point forward without careful memory management!

        // Set reentrancy lock, get initial balance, and begin preparing Permit2 call data.
        (uint256 id, uint256 initialBalance, uint256 m, uint256 typestringMemoryLocation) = _setReentrancyLockAndStartPreparingPermit2Call(token);
        // Memory gets overwritten and looks now as follows:
        // -> memory pointer offset
        // [ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ] <- memory content
        // [ selector ][ token    ][ amount   ][ nonce    ][ deadline  ][ this addr ][ amount   ][ depositor ][    ---    ][    320    ]
        // [ 0 bytes  ][ 32 bytes ][ 64 bytes ][ 96 bytes ][ 128 bytes ][ 160 bytes ][ 192 bytes][ 224 bytes ][ 256 bytes ][ 288 bytes ] <- memory offset


        // Insert the CompactDeposit typestring fragment.
        typestringMemoryLocation.insertCompactDepositTypestring();
        // Memory is now set up as follows:
        // -> memory pointer offset
        // [ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ] <- memory content
        // [ selector ][ token    ][ amount   ][ nonce    ][ deadline  ][ this addr ][ amount   ][ depositor ][    ---    ][    320    ]
        // [ 0 bytes  ][ 32 bytes ][ 64 bytes ][ 96 bytes ][ 128 bytes ][ 160 bytes ][ 192 bytes][ 224 bytes ][ 256 bytes ][ 288 bytes ] <- memory offset
        // ...
        // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ][ 22 bytes  ] <- memory content
        // [   ---     ][ frgmtLength ][ fragment1 ][ fragment2 ][ fragment3 ][ fragment4 ][ fragment5 ]
        // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][ 448 bytes ][ 480 bytes ][ 512 bytes ] <- memory offset


        // Store the CompactDeposit witness hash.
        assembly ("memory-safe") {
            // The witness hash is stored at an offset of 256 bytes (between the depositor and the number "320")
            mstore(add(m, 0x100), witness)
        }
        // Memory is now set up as follows:
        // -> memory pointer offset
        // [ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes ][ 32 bytes  ][ 32 bytes    ][ 32 bytes  ] <- memory content
        // [ selector ][ token    ][ amount   ][ nonce    ][ deadline  ][ this addr ][ amount   ][ depositor ][ witnessHash ][    320    ]
        // [ 0 bytes  ][ 32 bytes ][ 64 bytes ][ 96 bytes ][ 128 bytes ][ 160 bytes ][ 192 bytes][ 224 bytes ][ 256 bytes   ][ 288 bytes ] <- memory offset
        // ...


        // Write the signature and perform the Permit2 call.
        _writeSignatureAndPerformPermit2Call(m, uint256(0x140).asStubborn(), uint256(0x200).asStubborn(), signature);
        // Explanation on why we point at 0x200 (512) instead of 0x220 (544):
        // While the signature is actually at memory pointer + 544 bytes (first length, then data), the pointer to the signature still needs to be 512 bytes.
        // The reason for this is, that the pointer is relative to the calldata and the signature is not accounted for in the memory pointer offset.
        // The signature length will therefor actually be at 512 bytes within the calldata, since the arguments start at memory pointer + 32 bytes.

        // Memory is now set up as follows:
        // -> memory pointer offset
        // [ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes ][ 32 bytes  ][ 32 bytes    ][ 32 bytes  ] <- memory content
        // [ selector ][ token    ][ amount   ][ nonce    ][ deadline  ][ this addr ][ amount   ][ depositor ][ witnessHash ][    320    ]
        // [ 0 bytes  ][ 32 bytes ][ 64 bytes ][ 96 bytes ][ 128 bytes ][ 160 bytes ][ 192 bytes][ 224 bytes ][ 256 bytes   ][ 288 bytes ] <- memory offset
        // ...
        // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ][ 22 bytes  ][ 10 bytes  ][ 32 bytes  ][ length of sig ] <- memory content
        // [   512     ][ frgmtLength ][ fragment1 ][ fragment2 ][ fragment3 ][ fragment4 ][ fragment5 ][    ---    ][ sigLength ][   signature   ]
        // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][ 448 bytes ][ 480 bytes ][ 512 bytes ][ 534 bytes ][ 544 bytes ][   576 bytes   ] <- memory offset

        // Note: It is now safe to modify the memory again from this point forward.


        // Deposit tokens based on the balance change from the Permit2 call.
        _checkBalanceAndDeposit(token, recipient, id, initialBalance);

        // Clear reentrancy lock.
        _clearReentrancyGuard();

        // Return the ERC6909 token identifier of the associated resource lock.
        return id;
    }

    /**
     * @notice Internal function for depositing ERC20 tokens using Permit2 authorization and
     * registering a compact. The depositor must approve Permit2 to transfer the tokens on its
     * behalf unless the token in question automatically grants approval to Permit2. The ERC6909
     * token amount received by the depositor is derived from the difference between the starting
     * and ending balance held in the resource lock, which may differ from the amount transferred
     * depending on the implementation details of the respective token. The Permit2 authorization
     * signed by the depositor must contain an Activation witness containing the id of the resource
     * lock and an associated Compact, BatchCompact, or MultichainCompact payload matching the
     * specified compact category.
     * @param token           The address of the ERC20 token to deposit.
     * @param depositor       The account signing the permit2 authorization and depositing the tokens.
     * @param resetPeriod     The duration after which the resource lock can be reset once a forced withdrawal is initiated.
     * @param claimHash       A bytes32 hash derived from the details of the compact.
     * @param compactCategory The category of the compact being registered (Compact, BatchCompact, or MultichainCompact).
     * @param witness         Additional data used in generating the claim hash.
     * @param signature       The Permit2 signature from the depositor authorizing the deposit.
     * @return                The ERC6909 token identifier of the associated resource lock.
     */
    function _depositAndRegisterViaPermit2(
        address token,
        address depositor, // also recipient
        ResetPeriod resetPeriod,
        bytes32 claimHash,
        CompactCategory compactCategory,
        string calldata witness,
        bytes calldata signature
    ) internal returns (uint256) {
        // Set reentrancy lock, get initial balance, and begin preparing Permit2 call data.
        (uint256 id, uint256 initialBalance, uint256 m, uint256 typestringMemoryLocation) = _setReentrancyLockAndStartPreparingPermit2Call(token);
        // Memory looks now as follows:
        // -> memory pointer offset
        // [ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ] <- memory content
        // [ selector ][ token    ][ amount   ][ nonce    ][ deadline  ][ this addr ][ amount   ][ depositor ][    ---    ][    320    ]
        // [ 0 bytes  ][ 32 bytes ][ 64 bytes ][ 96 bytes ][ 128 bytes ][ 160 bytes ][ 192 bytes][ 224 bytes ][ 256 bytes ][ 288 bytes ] <- memory offset

        // Continue preparing Permit2 call data and get activation and compact typehashes.
        (bytes32 activationTypehash, bytes32 compactTypehash) = typestringMemoryLocation.writeWitnessAndGetTypehashes(compactCategory, witness, bool(false).asStubborn());

        // Memory example for non-batch, single-chain compact:
        // ...
        // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  9 bytes  ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  16 bytes   ] <- memory content
        // [   ---     ][     231     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ]
        // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  425 bytes  ][  457 bytes  ][  489 bytes  ][  521 bytes  ] <- memory offset
        // ...
        // [  ?? bytes ][   31 bytes   ][   15 bytes   ] <- memory content
        // [  witness  ][ tknFragment1 ][ tknFragment2 ]
        // [ 537 bytes ][ 569(?) bytes ][ 600 (?) bytes] <- memory offset


        // Derive the activation witness hash (keccak256(activationTypehash, id, claimHash)) and store it at an offset of 256 bytes (0x100).
        activationTypehash.deriveAndWriteWitnessHash(id, claimHash, m, 0x100);

        // Memory looks now as follows:
        // -> memory pointer offset
        // [ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes ][ 32 bytes  ][    32 bytes    ][ 32 bytes  ] <- memory content
        // [ selector ][ token    ][ amount   ][ nonce    ][ deadline  ][ this addr ][ amount   ][ depositor ][ actWitnessHash ][    320    ]
        // [ 0 bytes  ][ 32 bytes ][ 64 bytes ][ 96 bytes ][ 128 bytes ][ 160 bytes ][ 192 bytes][ 224 bytes ][   256 bytes    ][ 288 bytes ] <- memory offset
        // ... (example for non-batch, single-chain compact) ...
        // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  9 bytes  ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  16 bytes   ] <- memory content
        // [   ---     ][     231     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ]
        // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  425 bytes  ][  457 bytes  ][  489 bytes  ][  521 bytes  ] <- memory offset
        // ...
        // [  ?? bytes ][   31 bytes   ][   15 bytes   ] <- memory content
        // [  witness  ][ tknFragment1 ][ tknFragment2 ]
        // [ 537 bytes ][ 569(?) bytes ][ 600 (?) bytes] <- memory offset

        // Derive signature offset value.
        uint256 signatureOffsetValue;
        assembly ("memory-safe") {
            signatureOffsetValue := and(add(mload(add(m, 0x160)), 0x17f), not(0x1f))
        }
        // mload(m + 352 (0x160)) = 231 (for non-batch, single-chain compact)
        // 231 + 383 (0x17f) = 614 bytes (for non-batch, single-chain compact)
        // and(614, not(0x1f)) = 608 bytes (for non-batch, single-chain compact)
        // signatureOffsetValue = 608 (for non-batch, single-chain compact)
        //
        // Explanation of and(..., not(0x1f)):
        // 0x1f = 0001 1111
        // not(0x1f) = 1110 0000
        // and([...], 1110 0000) will eliminate the last 5 bits, effectively rounding down to the nearest multiple of 32

        // Write the signature and perform the Permit2 call.
        _writeSignatureAndPerformPermit2Call(m, uint256(0x140).asStubborn(), signatureOffsetValue, signature);

        // Memory looks now as follows:
        // -> memory pointer offset
        // [ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes ][ 32 bytes  ][    32 bytes    ][    32 bytes      ] <- memory content
        // [ selector ][ token    ][ amount   ][ nonce    ][ deadline  ][ this addr ][ amount   ][ depositor ][ actWitnessHash ][ 320 (ts pointer) ]
        // [ 0 bytes  ][ 32 bytes ][ 64 bytes ][ 96 bytes ][ 128 bytes ][ 160 bytes ][ 192 bytes][ 224 bytes ][   256 bytes    ][    288 bytes     ] <- memory offset
        // ... (example for non-batch, single-chain compact) ...
        // [     32 bytes      ][     32 bytes    ][ 32 bytes  ][  9 bytes  ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  16 bytes   ] <- memory content
        // [ 608 (sig pointer) ][ 231 (ts length) ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ]
        // [    320 bytes      ][    352 bytes    ][ 384 bytes ][ 416 bytes ][  425 bytes  ][  457 bytes  ][  489 bytes  ][  521 bytes  ] <- memory offset
        // ...
        // [  ?? bytes ][   31 bytes   ][   15 bytes   ][    25 bytes   ][   32 bytes    ][  64/65 bytes  ] <- memory content
        // [  witness  ][ tknFragment1 ][ tknFragment2 ][ ------------- ][   sigLength   ][   signature   ]
        // [ 537 bytes ][ 569(?) bytes ][ 600 (?) bytes][ 615 (?) bytes ][ 640 (?) bytes ][ 672 (?) bytes ] <- memory offset

        // WHAT IS THE TOKEN FRAGMENT USED FOR? IT IS NOT INCLUDED IN THE activationTypehash. WHY DOES THE FINAL WITNESS HASH LOOK LIKE IT IS?

        // Deposit tokens based on the balance change from the Permit2 call.
        _checkBalanceAndDeposit(token, depositor, id, initialBalance);

        // Register the compact.
        depositor.registerCompact(claimHash, compactTypehash, resetPeriod);

        // Clear reentrancy lock.
        _clearReentrancyGuard();

        // Return the ERC6909 token identifier of the associated resource lock.
        return id;
    }

    /**
     * @notice Internal function for depositing multiple tokens using Permit2 authorization in a
     * single transaction. The first token id can optionally represent native tokens by providing
     * the null address and an amount matching msg.value. The depositor must approve Permit2 to
     * transfer the tokens on its behalf unless the tokens automatically grant approval to
     * Permit2. The ERC6909 token amounts received by the recipient are derived from the
     * differences between starting and ending balances held in the resource locks, which may
     * differ from the amounts transferred depending on the implementation details of the
     * respective tokens. The Permit2 authorization signed by the depositor must contain a
     * CompactDeposit witness containing the allocator, the reset period, the scope, and the
     * intended recipient of the deposits.
     * @param permitted   Array of token permissions specifying the deposited tokens and amounts.
     * @param recipient   The address that will receive the corresponding ERC6909 tokens.
     * @param signature   The Permit2 signature from the depositor authorizing the deposits.
     * @return            Array of ERC6909 token identifiers for the associated resource locks.
     */
    function _depositBatchViaPermit2(ISignatureTransfer.TokenPermissions[] calldata permitted, address recipient, bytes calldata signature) internal returns (uint256[] memory) {
        // Set reentrancy guard, perform initial native deposit if present, and get initial token balances.
        (uint256 totalTokensLessInitialNative, bool firstUnderlyingTokenIsNative, uint256[] memory ids, uint256[] memory initialTokenBalances) = _preprocessAndPerformInitialNativeDeposit(permitted, recipient);

        // Derive the CompactDeposit witness hash.
        bytes32 witness = uint256(0x84).asStubborn().deriveCompactDepositWitnessHash();

        // Begin preparing Permit2 call data.
        (uint256 m, uint256 typestringMemoryLocation) = totalTokensLessInitialNative.beginPreparingBatchDepositPermit2Calldata(firstUnderlyingTokenIsNative);

        // Insert the CompactDeposit typestring fragment.
        typestringMemoryLocation.insertCompactDepositTypestring();

        // Declare variable for signature offset value.
        uint256 signatureOffsetValue;
        assembly ("memory-safe") {
            // Store the CompactDeposit witness hash.
            mstore(add(m, 0x80), witness)

            // Derive signature offset value.
            signatureOffsetValue := add(0x220, shl(7, totalTokensLessInitialNative))
        }

        // Write the signature and perform the Permit2 call.
        _writeSignatureAndPerformPermit2Call(m, uint256(0xc0).asStubborn(), signatureOffsetValue, signature);

        // Deposit tokens based on balance changes from Permit2 call and clear reentrancy lock.
        _verifyBalancesAndPerformDeposits(ids, permitted, initialTokenBalances, recipient, firstUnderlyingTokenIsNative);

        // Return the ERC6909 token identifiers of the associated resource locks.
        return ids;
    }

    /**
     * @notice Internal function for depositing multiple tokens using Permit2 authorization and
     * registering a compact in a single transaction. The first token id can optionally represent
     * native tokens by providing the null address and an amount matching msg.value. The depositor
     * must approve Permit2 to transfer the tokens on its behalf unless the tokens automatically
     * grant approval to Permit2. The ERC6909 token amounts received by the depositor are derived
     * from the differences between starting and ending balances held in the resource locks, which
     * may differ from the amounts transferred depending on the implementation details of the
     * respective tokens. The Permit2 authorization signed by the depositor must contain a
     * BatchActivation witness containing the ids of the resource locks and an associated
     * Compact, BatchCompact, or MultichainCompact payload matching the specified compact category.
     * @param depositor       The account signing the permit2 authorization and depositing the tokens.
     * @param permitted       Array of token permissions specifying the deposited tokens and amounts.
     * @param resetPeriod     The duration after which the resource locks can be reset once forced withdrawals are initiated.
     * @param claimHash       A bytes32 hash derived from the details of the compact.
     * @param compactCategory The category of the compact being registered (Compact, BatchCompact, or MultichainCompact).
     * @param witness         Additional data used in generating the claim hash.
     * @param signature       The Permit2 signature from the depositor authorizing the deposits.
     * @return                Array of ERC6909 token identifiers for the associated resource locks.
     */
    function _depositBatchAndRegisterViaPermit2(
        address depositor,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        ResetPeriod resetPeriod,
        bytes32 claimHash,
        CompactCategory compactCategory,
        string calldata witness,
        bytes calldata signature
    ) internal returns (uint256[] memory) {
        // Set reentrancy guard, perform initial native deposit if present, and get initial token balances.
        (uint256 totalTokensLessInitialNative, bool firstUnderlyingTokenIsNative, uint256[] memory ids, uint256[] memory initialTokenBalances) = _preprocessAndPerformInitialNativeDeposit(permitted, depositor);

        // Derive the hash of the resource lock ids.
        uint256 idsHash;
        assembly ("memory-safe") {
            idsHash := keccak256(add(ids, 0x20), shl(5, add(totalTokensLessInitialNative, firstUnderlyingTokenIsNative)))
        }

        // Begin preparing Permit2 call data.
        (uint256 m, uint256 typestringMemoryLocation) = totalTokensLessInitialNative.beginPreparingBatchDepositPermit2Calldata(firstUnderlyingTokenIsNative);

        // Prepare the typestring fragment and get batch activation and compact typehashes.
        (bytes32 activationTypehash, bytes32 compactTypehash) = typestringMemoryLocation.writeWitnessAndGetTypehashes(compactCategory, witness, bool(true).asStubborn());

        // Derive the batch activation witness hash and store it.
        activationTypehash.deriveAndWriteWitnessHash(idsHash, claimHash, m, 0x80);

        // Declare variable for signature offset value.
        uint256 signatureOffsetValue;
        assembly ("memory-safe") {
            // Get the length of the witness.
            let witnessLength := witness.length

            // Derive the total memory offset for the witness.
            let totalWitnessMemoryOffset := and(add(add(0xf3, add(witnessLength, iszero(iszero(witnessLength)))), add(mul(eq(compactCategory, 1), 0x0b), shl(6, eq(compactCategory, 2)))), not(0x1f))

            // Derive the signature offset value.
            signatureOffsetValue := add(add(0x180, shl(7, totalTokensLessInitialNative)), totalWitnessMemoryOffset)
        }

        // Write the signature and perform the Permit2 call.
        _writeSignatureAndPerformPermit2Call(m, uint256(0xc0).asStubborn(), signatureOffsetValue, signature);

        // Deposit tokens based on balance changes from Permit2 call and clear reentrancy lock.
        _verifyBalancesAndPerformDeposits(ids, permitted, initialTokenBalances, depositor, firstUnderlyingTokenIsNative);

        // Register the compact.
        depositor.registerCompact(claimHash, compactTypehash, resetPeriod);

        // Return the ERC6909 token identifiers of the associated resource locks.
        return ids;
    }

    /**
     * @notice Private function for pre-processing and performing an initial native deposit.
     * @param permitted                     Array of token permissions specifying the deposited tokens and amounts.
     * @param recipient                     The address that will receive the corresponding ERC6909 tokens.
     * @return totalTokensLessInitialNative The total number of tokens less the initial native deposit.
     * @return firstUnderlyingTokenIsNative A boolean indicating whether the first underlying token is native.
     * @return ids                          Array of ERC6909 token identifiers.
     * @return initialTokenBalances         Array of initial token balances.
     */
    function _preprocessAndPerformInitialNativeDeposit(ISignatureTransfer.TokenPermissions[] calldata permitted, address recipient)
        private
        returns (uint256 totalTokensLessInitialNative, bool firstUnderlyingTokenIsNative, uint256[] memory ids, uint256[] memory initialTokenBalances)
    {
        // Set reentrancy guard.
        _setReentrancyGuard();

        // Get total number of tokens and declare allocator, reset period, & scope variables.
        uint256 totalTokens = permitted.length;
        address allocator;
        ResetPeriod resetPeriod;
        Scope scope;

        assembly ("memory-safe") {
            // Get the offset of the permitted calldata struct.
            let permittedOffset := permitted.offset

            // Determine if the first underlying token is native.
            firstUnderlyingTokenIsNative := iszero(shr(96, shl(96, calldataload(permittedOffset))))

            // Revert if:
            //  * the array is empty
            //  * the callvalue is zero but the first token is native
            //  * the callvalue is nonzero but the first token is non-native
            //  * the first token is non-native and the callvalue doesn't equal the first amount
            if or(iszero(totalTokens), or(eq(firstUnderlyingTokenIsNative, iszero(callvalue())), and(firstUnderlyingTokenIsNative, iszero(eq(callvalue(), calldataload(add(permittedOffset, 0x20))))))) {
                // revert InvalidBatchDepositStructure()
                mstore(0, 0xca0fc08e)
                revert(0x1c, 0x04)
            }

            // Retrieve allocator, reset period, & scope.
            // NOTE: these may need to be sanitized if toIdIfRegistered doesn't already handle for it
            allocator := calldataload(0x84)
            resetPeriod := calldataload(0xa4)
            scope := calldataload(0xc4)
        }

        // Get the initial resource lock id.
        uint256 initialId = address(0).toIdIfRegistered(scope, resetPeriod, allocator);

        // Allocate ids array.
        ids = new uint256[](totalTokens);

        // Perform initial native deposit if present.
        if (firstUnderlyingTokenIsNative) {
            _deposit(recipient, initialId, msg.value);

            // Set the initial id using the native resource lock.
            ids[0] = initialId;
        }

        // Calculate total number of tokens less the initial native deposit.
        unchecked {
            totalTokensLessInitialNative = totalTokens - firstUnderlyingTokenIsNative.asUint256();
        }

        // Prepare ids and get initial token balances.
        initialTokenBalances = _prepareIdsAndGetBalances(ids, totalTokensLessInitialNative, firstUnderlyingTokenIsNative, permitted, initialId);
    }

    /**
     * @notice Private function for setting the reentrancy guard and starting the process
     *  of preparing a Permit2 call.
     * @param token                      The address of the token to be deposited.
     * @return id                        The ERC6909 token identifier of the associated resource lock.
     * @return initialBalance            The initial balance of the token in the contract.
     * @return m                         The memory pointer for the Permit2 call data.
     * @return typestringMemoryLocation  The memory location for the typestring.
     */
    function _setReentrancyLockAndStartPreparingPermit2Call(address token) private returns (uint256 id, uint256 initialBalance, uint256 m, uint256 typestringMemoryLocation) {
        // Set reentrancy guard.
        _setReentrancyGuard();

        // Declare allocator, reset period, & scope variables.
        address allocator;
        ResetPeriod resetPeriod;
        Scope scope;

        // Retrieve allocator, reset period, & scope.
        assembly ("memory-safe") {
            allocator := calldataload(0xa4)     // load at offset of 0xa4 = 164 bytes
            resetPeriod := calldataload(0xc4)   // load at offset of 0xc4 = 196 bytes
            scope := calldataload(0xe4)         // load at offset of 0xe4 = 228 bytes
        }

            // Example calldata to prove locations:
            //
            // 0x10d82672| 4 bytes
            // 0...0c36442b4a4522e871399cd717abdd847ab11fe88| 32 bytes token        <- offset of 4 bytes
            // 0...00000000000000000000000000000000000000001| 32 bytes amount       <- offset of 36 bytes
            // 0...00000000000000000000000000000000000000002| 32 bytes nonce        <- offset of 68 bytes
            // 0...00000000000000000000000000000000000000003| 32 bytes deadline     <- offset of 100 bytes
            // 0...0c36442b4a4522e871399cd717abdd847ab11fe88| 32 bytes depositor    <- offset of 132 bytes
            // 0...0c36442b4a4522e871399cd717abdd847ab11fe88| 32 bytes allocator    <- offset of 164 bytes
            // 0...00000000000000000000000000000000000000004| 32 bytes resetPeriod  <- offset of 196 bytes
            // 0...00000000000000000000000000000000000000001| 32 bytes scope        <- offset of 228 bytes
            // 0...0c36442b4a4522e871399cd717abdd847ab11fe88| 32 bytes recipient    <- offset of 260 bytes
            // 0...00000000000000000000000000000000000000140| 32 bytes signature offset
            // 0...00000000000000000000000000000000000000002| 32 bytes signature length
            // 12340000000000000000000000000000000000000...0| 32 bytes signature data

        // Get the ERC6909 token identifier of the associated resource lock.
        id = token.excludingNative().toIdIfRegistered(scope, resetPeriod, allocator);

        // Get the initial balance of the token in the contract.
        initialBalance = token.balanceOf(address(this));

        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            m := mload(0x40)

            // Begin preparing Permit2 call data.
            mstore(m, _PERMIT_WITNESS_TRANSFER_FROM_SELECTOR)
            // Copy calldata from 4-132 bytes (see proof above) at memory offset of 32 bytes
            calldatacopy(add(m, 0x20), 0x04, 0x80) // token, amount, nonce, deadline
            // store an empty address at memory offset of 160 bytes
            mstore(add(m, 0xa0), address())
            // store the amount (36 bytes into the calldata) at memory offset of 192 bytes
            mstore(add(m, 0xc0), calldataload(0x24)) // amount
            // store the depositor (132 bytes into the calldata) at memory offset of 224 bytes
            mstore(add(m, 0xe0), calldataload(0x84)) // depositor
            // store the pointer 320 at memory offset of 288 bytes (320 bytes is the pointer relative to the start of the calldata, thats why it is not 352)
            mstore(add(m, 0x120), 0x140) // the 32 bytes gap at 256 bytes will be filled with the witness hash

            // Derive the memory location for the typestring (352 bytes into the memory)
            typestringMemoryLocation := add(m, 0x160) // the 32 bytes gap at 320 is left empty for the witness pointer 

            // NOTE: strongly consider allocating memory here as the inline assembly scope
            // is being left (it *should* be fine for now as the function between assembly
            // blocks does not allocate any new memory).

            // Memory is now set up as follows:
            // -> memory pointer offset
            // [ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ] <- memory content
            // [ selector ][ token    ][ amount   ][ nonce    ][ deadline  ][ this addr ][ amount   ][ depositor ][    ---    ][    320    ]
            // [ 0 bytes  ][ 32 bytes ][ 64 bytes ][ 96 bytes ][ 128 bytes ][ 160 bytes ][ 192 bytes][ 224 bytes ][ 256 bytes ][ 288 bytes ] <- memory offset
        }
    }

    /**
     * @notice Private function for writing the signature and performing the Permit2 call.
     * @param m                       The memory pointer for the Permit2 call data.
     * @param signatureOffsetLocation The memory location for the signature offset.
     * @param signatureOffsetValue    The signature offset value.
     * @param signature               The Permit2 signature.
     */
    function _writeSignatureAndPerformPermit2Call(uint256 m, uint256 signatureOffsetLocation, uint256 signatureOffsetValue, bytes calldata signature) private {
        // Determine if Permit2 is deployed.
        bool isPermit2Deployed = _isPermit2Deployed();

        assembly ("memory-safe") {
            // Write the signature offset.
            mstore(add(m, signatureOffsetLocation), signatureOffsetValue) // signature offset

            // Retrieve signature length and derive signature memory offset.
            let signatureLength := signature.length
            let signatureMemoryOffset := add(m, add(0x20, signatureOffsetValue)) // memory + 32 + signatureOffsetValue (544 for TheCompact.deposit())

            // Write the signature length.
            mstore(signatureMemoryOffset, signatureLength)

            // Copy the signature from calldata to memory.
            calldatacopy(add(signatureMemoryOffset, 0x20), signature.offset, signatureLength)

            // Memory is now set up as follows (for TheCompact.deposit()):
            // -> memory pointer offset
            // [ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes ][ 32 bytes  ][ 32 bytes    ][ 32 bytes  ] <- memory content
            // [ selector ][ token    ][ amount   ][ nonce    ][ deadline  ][ this addr ][ amount   ][ depositor ][ witnessHash ][    320    ]
            // [ 0 bytes  ][ 32 bytes ][ 64 bytes ][ 96 bytes ][ 128 bytes ][ 160 bytes ][ 192 bytes][ 224 bytes ][ 256 bytes   ][ 288 bytes ] <- memory offset
            // ...
            // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ][ 22 bytes  ][ 10 bytes  ][ 32 bytes  ][  64/65 bytes  ] <- memory content
            // [   512     ][ frgmtLength ][ fragment1 ][ fragment2 ][ fragment3 ][ fragment4 ][ fragment5 ][    ---    ][ sigLength ][   signature   ]
            // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][ 448 bytes ][ 480 bytes ][ 512 bytes ][ 534 bytes ][ 544 bytes ][   576 bytes   ] <- memory offset


            // Perform the Permit2 call.
            if iszero(and(isPermit2Deployed, call(gas(), _PERMIT2, 0, add(m, 0x1c), add(0x24, add(signatureOffsetValue, signatureLength)), 0, 0))) {
                // send from memory: m + bytes 28 to (576 + signatureLength)

                // Calldata:
                // 0x137c29fe       <- permit2.permitWitnessTransferFrom function selector
                // token,amount     <- TokenPermissions struct in PermitTransferFrom struct
                // nonce,deadline   <- PermitTransferFrom struct
                // address(this)    <- to in SignatureTransferDetails struct
                // amount           <- requestedAmount in SignatureTransferDetails struct
                // depositor        <- owner
                // witnessHash      <- witness
                // pointer(320)     <- wittnessTypeString
                // pointer(512)     <- signature
                // length,fragment          <- wittnessTypeString
                // length,signature         <- signature



                // Example calldata of how a call to permitWitnessTransferFrom needs to look like:
                //
                // 0x137c29fe                                                       <- permit2.permitWitnessTransferFrom function selector
                // 00000000000000000000000071159a834d69273CCA5C9404C3D549AE7C67B2EA <- offset 0 bytes (0x00)    <- address token
                // 0000000000000000000000000000000000000000000000000000000000000001 <- offset 32 bytes (0x20)   <- uint256 amount
                // 0000000000000000000000000000000000000000000000000000000000000002 <- offset 64 bytes (0x40)   <- uint256 nonce
                // 0000000000000000000000000000000000000000000000000000000000000003 <- offset 96 bytes (0x60)   <- uint256 deadline
                // 00000000000000000000000071159a834d69273CCA5C9404C3D549AE7C67B2EA <- offset 128 bytes (0x80)  <- address to
                // 0000000000000000000000000000000000000000000000000000000000000004 <- offset 160 bytes (0xa0)  <- uint256 requestedAmount
                // 00000000000000000000000071159a834d69273CCA5C9404C3D549AE7C67B2EA <- offset 192 bytes (0xc0)  <- address owner
                // 9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658 <- offset 224 bytes (0xe0)  <- bytes32 witness
                // 0000000000000000000000000000000000000000000000000000000000000140 <- offset 256 bytes (0x100) <- string witnessTypeString (pointer)
                // 0000000000000000000000000000000000000000000000000000000000000180 <- offset 288 bytes (0x120) <- bytes signature (pointer)
                // 0000000000000000000000000000000000000000000000000000000000000015 <- offset 320 bytes (0x140) <- witnessTypeString length
                // 5769746e6573732875696e743235362074657374290000000000000000000000 <- offset 352 bytes (0x160) <- witnessTypeString
                // 0000000000000000000000000000000000000000000000000000000000000002 <- offset 384 bytes (0x180) <- signature length
                // 1234000000000000000000000000000000000000000000000000000000000000 <- offset 416 bytes (0x1a0) <- signature

                // Bubble up if the call failed and there's data.
                // NOTE: consider evaluating remaining gas to protect against revert bombing
                if returndatasize() {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }

                // revert Permit2CallFailed();
                mstore(0, 0x7f28c61e)
                revert(0x1c, 0x04)
            }
        }
    }

    /**
     * @notice Private function for verifying balance changes and performing deposits.
     * @param ids                          The ERC6909 token identifiers of the associated resource locks.
     * @param permittedTokens              The token permissions specifying the deposited tokens and amounts.
     * @param initialTokenBalances         The initial token balances in the contract.
     * @param recipient                    The address that will receive the corresponding ERC6909 tokens.
     * @param firstUnderlyingTokenIsNative A boolean indicating whether the first underlying token is native.
     */
    function _verifyBalancesAndPerformDeposits(
        uint256[] memory ids,
        ISignatureTransfer.TokenPermissions[] calldata permittedTokens,
        uint256[] memory initialTokenBalances,
        address recipient,
        bool firstUnderlyingTokenIsNative
    ) private {
        // Declare token balance, initial balance, and error buffer variables.
        uint256 tokenBalance;
        uint256 initialBalance;
        uint256 errorBuffer;

        // Retrieve total initial token balances (equal to total tokens less initial native deposit).
        uint256 totalTokensLessInitialNative = initialTokenBalances.length;

        unchecked {
            // Iterate through each token.
            for (uint256 i = 0; i < totalTokensLessInitialNative; ++i) {
                // Get the token balance and initial balance.
                tokenBalance = permittedTokens[i + firstUnderlyingTokenIsNative.asUint256()].token.balanceOf(address(this));
                initialBalance = initialTokenBalances[i];

                // Set the error buffer if the initial balance is greater than or equal to the token balance.
                errorBuffer |= (initialBalance >= tokenBalance).asUint256();

                // Perform the deposit.
                _deposit(recipient, ids[i + firstUnderlyingTokenIsNative.asUint256()], tokenBalance - initialBalance);
            }
        }

        assembly ("memory-safe") {
            // Revert if the error buffer is set.
            if errorBuffer {
                // revert InvalidDepositBalanceChange()
                mstore(0, 0x426d8dcf)
                revert(0x1c, 0x04)
            }
        }

        // Clear reentrancy guard.
        _clearReentrancyGuard();
    }

    /**
     * @notice Private function for preparing ids and getting token balances.
     * Note that all tokens must be supplied in ascending order and cannot be duplicated.
     * @param ids                          The ERC6909 token identifiers of the associated resource locks.
     * @param totalTokensLessInitialNative The total number of tokens less the initial native deposit.
     * @param firstUnderlyingTokenIsNative A boolean indicating whether the first underlying token is native.
     * @param permitted                    The token permissions specifying the deposited tokens and amounts.
     * @param id                           The ERC6909 token identifier of the associated resource lock.
     * @return tokenBalances               The token balances in the contract.
     */
    function _prepareIdsAndGetBalances(uint256[] memory ids, uint256 totalTokensLessInitialNative, bool firstUnderlyingTokenIsNative, ISignatureTransfer.TokenPermissions[] calldata permitted, uint256 id)
        private
        view
        returns (uint256[] memory tokenBalances)
    {
        unchecked {
            // Allocate token balances array.
            tokenBalances = new uint256[](totalTokensLessInitialNative);

            // Declare token, candidate id, and error buffer variables.
            address token;
            uint256 candidateId;
            uint256 errorBuffer;

            // Iterate over each token.
            for (uint256 i = 0; i < totalTokensLessInitialNative; ++i) {
                // Retrieve the token and derive the candidate id.
                token = permitted[i + firstUnderlyingTokenIsNative.asUint256()].token;
                candidateId = id.withReplacedToken(token);

                // Set the error buffer if the candidate id is less than or equal to the current id.
                errorBuffer |= (candidateId <= id).asUint256();

                // Update the id.
                id = candidateId;

                // Set the id in the ids array.
                ids[i + firstUnderlyingTokenIsNative.asUint256()] = id;

                // Get the token balance and set it in the token balances array.
                tokenBalances[i] = token.balanceOf(address(this));
            }

            assembly ("memory-safe") {
                // Revert if the error buffer is set.
                if errorBuffer {
                    // revert InvalidDepositTokenOrdering()
                    mstore(0, 0x0f2f1e51)
                    revert(0x1c, 0x04)
                }
            }
        }
    }
}
