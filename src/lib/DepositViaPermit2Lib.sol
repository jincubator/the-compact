// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { CompactCategory } from "../types/CompactCategory.sol";
import {
    COMPACT_TYPEHASH,
    BATCH_COMPACT_TYPEHASH,
    MULTICHAIN_COMPACT_TYPEHASH,
    PERMIT2_DEPOSIT_WITNESS_FRAGMENT_HASH,
    PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE,
    PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO,
    PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE,
    PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO,
    TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_ONE,
    TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_TWO,
    COMPACT_ACTIVATION_TYPEHASH,
    BATCH_COMPACT_ACTIVATION_TYPEHASH,
    MULTICHAIN_COMPACT_ACTIVATION_TYPEHASH,
    COMPACT_BATCH_ACTIVATION_TYPEHASH,
    BATCH_COMPACT_BATCH_ACTIVATION_TYPEHASH,
    MULTICHAIN_COMPACT_BATCH_ACTIVATION_TYPEHASH,
    PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_ONE,
    PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_TWO,
    PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_THREE,
    PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
    PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
    PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
    PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE,
    PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO,
    PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE,
    PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SIX,
    COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_ONE,
    COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_TWO,
    COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_THREE,
    COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_FOUR,
    COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_FIVE
} from "../types/EIP712Types.sol";

/**
 * @title DepositViaPermit2Lib
 * @notice Library contract implementing internal functions with logic for processing
 * token deposits via permit2. These deposits leverage Permit2 witness data to either
 * indicate the parameters of the lock to deposit into and the recipient of the deposit,
 * or the parameters of the compact to register alongside the deposit. Deposits can also
 * involve a single ERC20 token or a batch of tokens in a single Permit2 authorization.
 * @dev IMPORTANT NOTE: this logic operates directly on unallocated memory, and reads
 * directly from fixed calldata offsets; proceed with EXTREME caution when making any
 * modifications to either this logic contract (including the insertion of new logic) or
 * to the associated permit2 deposit function interfaces!
 */
library DepositViaPermit2Lib {
    // Selector for the batch `permit2.permitWitnessTransferFrom` function.
    uint256 private constant _BATCH_PERMIT_WITNESS_TRANSFER_FROM_SELECTOR = 0xfe8ec1a7;

    /**
     * @notice Internal view function for preparing batch deposit permit2 calldata.
     * Prepares known arguments and offsets in memory and returns pointers to the start
     * of the prepared calldata as well as to the start of the witness typestring.
     * @param totalTokensLessInitialNative The number of non-native tokens to deposit.
     * @param firstUnderlyingTokenIsNative Whether the first underlying token is native.
     * @return m The memory pointer to the start of the prepared calldata.
     * @return typestringMemoryLocation The memory pointer to the start of the typestring.
     */
    function beginPreparingBatchDepositPermit2Calldata(uint256 totalTokensLessInitialNative, bool firstUnderlyingTokenIsNative) internal view returns (uint256 m, uint256 typestringMemoryLocation) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            m := mload(0x40)

            // Derive size of each token chunk (2 words per token).
            let tokenChunk := shl(6, totalTokensLessInitialNative)

            // Derive size of two token chunks (4 words per token).
            let twoTokenChunks := shl(1, tokenChunk)

            // Derive memory location of the `permitted` calldata struct.
            let permittedCalldataLocation := add(add(0x24, calldataload(0x24)), shl(6, firstUnderlyingTokenIsNative))

            // Prepare the initial fragment of the witness typestring.
            mstore(m, _BATCH_PERMIT_WITNESS_TRANSFER_FROM_SELECTOR)
            mstore(add(m, 0x20), 0xc0) // permitted offset
            mstore(add(m, 0x40), add(0x140, tokenChunk)) // details offset
            mstore(add(m, 0x60), calldataload(0x04)) // depositor
            // Skip witnessHash at 0x80 as it is not yet known.
            mstore(add(m, 0xa0), add(0x160, twoTokenChunks)) // witness offset
            // Skip signatureOffset at 0xc0 as it is not yet known.
            mstore(add(m, 0xe0), 0x60) // permitted tokens relative offset
            mstore(add(m, 0x100), calldataload(0x44)) // nonce
            mstore(add(m, 0x120), calldataload(0x64)) // deadline
            mstore(add(m, 0x140), totalTokensLessInitialNative) // permitted.length

            // Copy permitted data from calldata to memory.
            calldatacopy(add(m, 0x160), permittedCalldataLocation, tokenChunk)

            // Derive memory location of the `details` calldata struct.
            let detailsOffset := add(add(m, 0x160), tokenChunk)

            // Store the length of the `details` array.
            mstore(detailsOffset, totalTokensLessInitialNative)

            // Derive start, next, & end locations for iterating through `details` array.
            let starting := add(detailsOffset, 0x20)
            let next := add(detailsOffset, 0x40)
            let end := shl(6, totalTokensLessInitialNative)

            // Iterate through `details` array and copy data from calldata to memory.
            for { let i := 0 } lt(i, end) { i := add(i, 0x40) } {
                // Copy this contract as the recipient address.
                mstore(add(starting, i), address())

                // Copy full token amount as the requested amount.
                mstore(add(next, i), calldataload(add(permittedCalldataLocation, add(0x20, i))))
            }

            // Derive memory location of the witness typestring.
            typestringMemoryLocation := add(m, add(0x180, twoTokenChunks))

            // NOTE: strongly consider allocating memory here as the inline assembly scope
            // is being left (it *should* be fine for now as the function between assembly
            // blocks does not allocate any new memory).
        }
    }

    /**
     * @notice Internal pure function for deriving typehashes and simultaneously
     * preparing the witness typestring component of the call to permit2.
     * @param memoryLocation      The memory pointer to the start of the typestring.
     * @param category            The CompactCategory of the deposit.
     * @param witness             The witness string to insert.
     * @param usingBatch          Whether the deposit involves a batch.
     * @return activationTypehash The derived activation typehash.
     * @return compactTypehash    The derived compact typehash.
     */
    function writeWitnessAndGetTypehashes(uint256 memoryLocation, CompactCategory category, string calldata witness, bool usingBatch)
        internal
        pure
        returns (bytes32 activationTypehash, bytes32 compactTypehash)
    {
        // memory location is 352

        // Memory looks now as follows:
        // -> memory pointer offset
        // [ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes ][ 32 bytes  ][ 32 bytes  ][ 32 bytes  ] <- memory content
        // [ selector ][ token    ][ amount   ][ nonce    ][ deadline  ][ this addr ][ amount   ][ depositor ][    ---    ][    320    ]
        // [ 0 bytes  ][ 32 bytes ][ 64 bytes ][ 96 bytes ][ 128 bytes ][ 160 bytes ][ 192 bytes][ 224 bytes ][ 256 bytes ][ 288 bytes ] <- memory offset

        assembly ("memory-safe") {
            // Internal assembly function for writing the witness and typehashes.
            // Used to enable leaving the inline assembly scope early when the
            // witness is empty (no-witness case).
            function writeWitnessAndGetTypehashes(memLocation, c, witnessOffset, witnessLength, usesBatch) -> derivedActivationTypehash, derivedCompactTypehash {
                // Derive memory offset for the witness typestring data.
                let memoryOffset := add(memLocation, 0x20) // memoryOffset = 352 + 32 = 384

                // Declare variables for start of Activation and Category-specific data.
                let activationStart
                let categorySpecificStart

                // Handle non-batch cases.
                if iszero(usesBatch) {
                    // Prepare initial Activation witness typestring fragment.
                    mstore(add(memoryOffset, 0x09), PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO) // length of 9 bytes
                    mstore(memoryOffset, PERMIT2_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE) // overrides empty bits of fragment two

                    // Set memory pointers for Activation and Category-specific data start.
                    activationStart := add(memoryOffset, 0x13)          // activationStart = 384 + 19 = 403
                    categorySpecificStart := add(memoryOffset, 0x29)    // categorySpecificStart = 384 + 41 = 425

                    // ...
                    // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  9 bytes  ] <- memory content
                    // [   ---     ][     ---     ][ fragment1 ][ fragment2 ]
                    // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ] <- memory offset
                }

                // Proceed with batch case if preparation of activation has not begun.
                if iszero(activationStart) {
                    // Prepare initial BatchActivation witness typestring fragment.
                    mstore(add(memoryOffset, 0x16), PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_TWO) // length of 22 bytes
                    mstore(memoryOffset, PERMIT2_BATCH_DEPOSIT_WITH_ACTIVATION_TYPESTRING_FRAGMENT_ONE) // overrides empty bits of fragment two

                    // Set memory pointers for Activation and Category-specific data.
                    activationStart := add(memoryOffset, 0x18) // activationStart = 384 + 24 = 408
                    categorySpecificStart := add(memoryOffset, 0x36) // categorySpecificStart = 384 + 54 = 438

                    // ...
                    // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  22 bytes ] <- memory content
                    // [   ---     ][     ---     ][ fragment1 ][ fragment2 ]
                    // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ] <- memory offset
                }

                // Declare variable for end of Category-specific data.
                let categorySpecificEnd

                // Handle CompactCategory.Compact (non-batch, single-chain) case.
                if iszero(c) {
                    // Prepare next typestring fragment using Compact witness typestring.
                    mstore(categorySpecificStart, PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_ONE)
                    mstore(add(categorySpecificStart, 0x20), PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_TWO)
                    mstore(add(categorySpecificStart, 0x50), PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_FOUR) // length of 16 bytes
                    mstore(add(categorySpecificStart, 0x40), PERMIT2_ACTIVATION_COMPACT_TYPESTRING_FRAGMENT_THREE) // overrides empty bits of fragment four

                    // Set memory pointers for Activation and Category-specific data end.
                    categorySpecificEnd := add(categorySpecificStart, 0x70) // categorySpecificEnd = 425/438 + 112 = 537/550
                    categorySpecificStart := add(categorySpecificStart, 0x10) // categorySpecificStart = 425/438 + 16 = 441/454

                    // if 'usesBatch' is false, memory looks like this:
                    // ...
                    // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  9 bytes  ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  16 bytes   ] <- memory content
                    // [   ---     ][     ---     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ]
                    // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  425 bytes  ][  457 bytes  ][  489 bytes  ][  521 bytes  ] <- memory offset

                    // if 'usesBatch' is true, memory looks like this:
                    // ...
                    // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  22 bytes ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  16 bytes   ] <- memory content
                    // [   ---     ][     ---     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ]
                    // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  438 bytes  ][  470 bytes  ][  502 bytes  ][  534 bytes  ] <- memory offset
                }

                // Handle CompactCategory.BatchCompact (single-chain) case.
                if iszero(sub(c, 1)) {
                    // Prepare next typestring fragment using BatchCompact witness typestring.
                    mstore(categorySpecificStart, PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE)
                    mstore(add(categorySpecificStart, 0x20), PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO)
                    mstore(add(categorySpecificStart, 0x5b), PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR) // length of 27 bytes
                    mstore(add(categorySpecificStart, 0x40), PERMIT2_ACTIVATION_BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE) // overrides empty bits of fragment four

                    // Set memory pointers for Activation and Category-specific data end.
                    categorySpecificEnd := add(categorySpecificStart, 0x7b) // categorySpecificEnd = 425/438 + 123 = 548/561
                    categorySpecificStart := add(categorySpecificStart, 0x15) // categorySpecificStart = 425/438 + 21 = 446/459

                    // if 'usesBatch' is false, memory looks like this:
                    // ...
                    // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  9 bytes  ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  27 bytes   ] <- memory content
                    // [   ---     ][     ---     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ]
                    // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  425 bytes  ][  457 bytes  ][  489 bytes  ][  521 bytes  ] <- memory offset

                    // if 'usesBatch' is true, memory looks like this:
                    // ...
                    // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  22 bytes ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  27 bytes   ] <- memory content
                    // [   ---     ][     ---     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ]
                    // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  438 bytes  ][  470 bytes  ][  502 bytes  ][  534 bytes  ] <- memory offset
                }

                // Handle CompactCategory.MultichainCompact case if preparation of compact fragment has not begun.
                if iszero(categorySpecificEnd) {
                    // Prepare next typestring fragment using Multichain & Segment witness typestring.
                    mstore(categorySpecificStart, PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_ONE)
                    mstore(add(categorySpecificStart, 0x20), PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_TWO)
                    mstore(add(categorySpecificStart, 0x40), PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_THREE)
                    mstore(add(categorySpecificStart, 0x60), PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FOUR)
                    mstore(add(categorySpecificStart, 0x90), PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_SIX) // length of 16 bytes
                    mstore(add(categorySpecificStart, 0x80), PERMIT2_ACTIVATION_MULTICHAIN_COMPACT_TYPESTRING_FRAGMENT_FIVE) // overrides empty bits of fragment six
                    // FRAGMENT FIVE NEEDS TO BE STARTING AT 0x80 TO NOT OVERRIDE FRAGMENT FOUR AND SIX NEEDS TO BE STARTING AT 0x90

                    // Set memory pointers for Activation and Category-specific data end.
                    categorySpecificEnd := add(categorySpecificStart, 0xb0) // categorySpecificEnd = 425/438 + 176 = 601/614
                    categorySpecificStart := add(categorySpecificStart, 0x1a) // categorySpecificStart = 425/438 + 26 = 451/464
                    // ENDS BASED ON WRONG 0x60 VALUE CALCULATION, SO 0xb0 INSTEAD OF 0x90

                    // if 'usesBatch' is false, memory looks like this:
                    // ...
                    // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  9 bytes  ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  16 bytes   ] <- memory content
                    // [   ---     ][     ---     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ][ c fragment5 ][ c fragment6 ]
                    // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  425 bytes  ][  457 bytes  ][  489 bytes  ][  521 bytes  ][  553 bytes  ][  585 bytes  ] <- memory offset (601)

                    // if 'usesBatch' is true, memory looks like this:
                    // ...
                    // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  22 bytes ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  16 bytes   ] <- memory content
                    // [   ---     ][     ---     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ][ c fragment5 ][ c fragment6 ]
                    // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  438 bytes  ][  470 bytes  ][  502 bytes  ][  534 bytes  ][  566 bytes  ][  598 bytes  ] <- memory offset (614)
                }

                // Handle no-witness cases.
                if iszero(witnessLength) {
                    // Derive memory offset for region used to retrieve typestring fragment by index.
                    let indexWords := shl(5, c)

                    // Prepare token permissions typestring fragment.
                    mstore(add(categorySpecificEnd, 0x0e), TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_TWO)
                    mstore(sub(categorySpecificEnd, 1), TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_ONE)

                    // Derive total length of typestring and store at start of memory.
                    mstore(memLocation, sub(add(categorySpecificEnd, 0x2e), memoryOffset))

                    // Retrieve and cache free memory pointer.
                    let m := mload(0x40)

                    // Derive activation typehash based on the compact category for non-batch cases.
                    if iszero(usesBatch) {
                        // Prepare typehashes for Activation.
                        mstore(0, COMPACT_ACTIVATION_TYPEHASH)
                        mstore(0x20, BATCH_COMPACT_ACTIVATION_TYPEHASH)
                        mstore(0x40, MULTICHAIN_COMPACT_ACTIVATION_TYPEHASH)

                        // Retrieve respective typehash by index.
                        derivedActivationTypehash := mload(indexWords)
                    }

                    // Derive activation typehash for batch cases if typehash is not yet derived.
                    if iszero(derivedActivationTypehash) {
                        // Prepare typehashes for BatchActivation.
                        mstore(0, COMPACT_BATCH_ACTIVATION_TYPEHASH)
                        mstore(0x20, BATCH_COMPACT_BATCH_ACTIVATION_TYPEHASH)
                        mstore(0x40, MULTICHAIN_COMPACT_BATCH_ACTIVATION_TYPEHASH)

                        // Retrieve respective typehash by index.
                        derivedActivationTypehash := mload(indexWords)
                    }

                    // Prepare compact typehashes.
                    mstore(0, COMPACT_TYPEHASH)
                    mstore(0x20, BATCH_COMPACT_TYPEHASH)
                    mstore(0x40, MULTICHAIN_COMPACT_TYPEHASH)

                    // Retrieve respective typehash by index.
                    derivedCompactTypehash := mload(indexWords)

                    // Restore the free memory pointer.
                    mstore(0x40, m)

                    // Leave the inline assembly scope early.
                    leave
                }
                // NEED TO CHECK NO-WITNESS CASES


                // Copy the supplied compact witness from calldata.
                calldatacopy(categorySpecificEnd, witnessOffset, witnessLength) // add the witness after the typestring in memory

                // Memory example for non-batch, single-chain compact:
                // ...
                // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  9 bytes  ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  16 bytes   ] <- memory content
                // [   ---     ][     ---     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ]
                // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  425 bytes  ][  457 bytes  ][  489 bytes  ][  521 bytes  ] <- memory offset
                // ...
                // [  xx bytes ] <- memory content
                // [  witness  ]
                // [ 537 bytes ] <- memory offset

                // Insert tokenPermissions typestring fragment.
                let tokenPermissionsFragmentStart := add(categorySpecificEnd, witnessLength)
                // we skip the first byte of fragment one, so the offset is 0x0e (14 bytes) instead of 0x0f (15 bytes)
                mstore(add(tokenPermissionsFragmentStart, 0x0e), TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_TWO) // length of 15 bytes
                mstore(sub(tokenPermissionsFragmentStart, 1), TOKEN_PERMISSIONS_TYPESTRING_FRAGMENT_ONE) // overrides empty bits of fragment two

                // THIS WILL OVERRIDE THE LAST BYTE OF THE WITNESS DATA, WHICH IS ALSO SUPPOSED TO BE A ')', SO IT WOULD NOT CHANGE ANYTHING.
                // AFTER TALKING TO 0age ABOUT THIS, A SOLUTION FOR VERSION 1 WOULD BE TO LIMIT THE WITNESSDATA TO THE INPUT OF THE STRUCT.
                //
                // EXAMPLE OF A PREVIOUS WITNESS:
                // Witness witness)Witness(uint256 witnessArgument)
                // THE NEW WITNESS WOULD LOOK LIKE THIS:
                // uint256 witnessArgument
                // 
                // THIS WOULD LEAD TO SMALLER CALLDATA. IT ALSO ENSURES THE REQUIREMENT OF EIP-712 THAT ALL STRUCT DEFINITIONS 
                // ARE ALPHANUMERICALLY ORDERED IN THE TYPESTRING, SO LESS PRONE TO ERRORS BY OTHER DEVELOPERS.


                // Memory example for non-batch, single-chain compact:
                // ...
                // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  9 bytes  ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  16 bytes   ] <- memory content
                // [   ---     ][     ---     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ]
                // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  425 bytes  ][  457 bytes  ][  489 bytes  ][  521 bytes  ] <- memory offset
                // ...
                // [  ?? bytes ][   31 bytes   ][   15 bytes   ] <- memory content
                // [  witness  ][ tknFragment1 ][ tknFragment2 ]
                // [ 537 bytes ][ 569(?) bytes ][ 600 (?) bytes] <- memory offset


                // Derive total length of typestring and store at start (352 bytes) of memory. (0x2e (46 bytes) = 32 bytes - 1 byte + 15 bytes)
                mstore(memLocation, sub(add(tokenPermissionsFragmentStart, 0x2e), memoryOffset))
                // Example calculation for non-batch, single-chain compact: (569 + 46) - 384 = 231

                // Memory example for non-batch, single-chain compact:
                // ...
                // [ 32 bytes  ][  32 bytes   ][ 32 bytes  ][  9 bytes  ][  32 bytes   ][  32 bytes   ][  32 bytes   ][  16 bytes   ] <- memory content
                // [   ---     ][     231     ][ fragment1 ][ fragment2 ][ c fragment1 ][ c fragment2 ][ c fragment3 ][ c fragment4 ]
                // [ 320 bytes ][  352 bytes  ][ 384 bytes ][ 416 bytes ][  425 bytes  ][  457 bytes  ][  489 bytes  ][  521 bytes  ] <- memory offset
                // ...
                // [  ?? bytes ][   31 bytes   ][   15 bytes   ] <- memory content
                // [  witness  ][ tknFragment1 ][ tknFragment2 ]
                // [ 537 bytes ][ 569(?) bytes ][ 600 (?) bytes] <- memory offset

                // Derive activation typehash.
                derivedActivationTypehash := keccak256(activationStart, sub(tokenPermissionsFragmentStart, activationStart))
                // Data hashed:
                // PERMIT2_(BATCH_)DEPOSIT_WITH_ACTIVATION_TYPESTRING (minus the first 19/24 bytes)
                // PERMIT2_ACTIVATION_(BATCH/MULTICHAIN_)COMPACT_TYPESTRING
                // witness calldata

                // Derive compact typehash.
                derivedCompactTypehash := keccak256(categorySpecificStart, sub(tokenPermissionsFragmentStart, categorySpecificStart))
                // Data hashed:
                // PERMIT2_ACTIVATION_(BATCH/MULTICHAIN_)COMPACT_TYPESTRING
                // witness calldata

                // Example of the full witness typestring for a non-batch deposit with a single-chained compact 
                // registration with an witness input of "Witness witness)Witness(uint256 witnessArgument)":
                // Activation witness)Activation(uint256 id,Compact compact)Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Witness witness)Witness(uint256 witnessArgument)TokenPermissions(address token,uint256 amount)
                // -------------------[ activation witness typestring .....................................................................................................................................................]
                // ---------------------------------------------------------[ compact witness typestring ..................................................................................................................]
            }

            // Execute internal assembly function and store derived typehashes.
            activationTypehash, compactTypehash := writeWitnessAndGetTypehashes(memoryLocation, category, witness.offset, witness.length, usingBatch)
        }
    }

    /**
     * @notice Internal pure function for deriving the activation witness hash and
     * writing it to a specified memory location.
     * @param activationTypehash The derived activation typehash.
     * @param idOrIdsHash        Resource lock ID or uint256 representation of the hash of each ID.
     * @param claimHash          The claim hash.
     * @param memoryPointer      The memory pointer to the start of the memory region.
     * @param offset             The offset within the memory region to write the witness hash.
     */
    function deriveAndWriteWitnessHash(bytes32 activationTypehash, uint256 idOrIdsHash, bytes32 claimHash, uint256 memoryPointer, uint256 offset) internal pure {
        assembly ("memory-safe") {
            // Retrieve and cache free memory pointer.
            let m := mload(0x40)

            // Prepare data for the witness hash: activationTypehash, idOrIdsHash & claimHash.
            mstore(0, activationTypehash)
            mstore(0x20, idOrIdsHash)
            mstore(0x40, claimHash)

            // Derive activation witness hash and write it to specified (256 bytes offset) memory location.
            mstore(add(memoryPointer, offset), keccak256(0, 0x60))

            // Restore the free memory pointer.
            mstore(0x40, m)
        }
    }

    /**
     * @notice Internal pure function for deriving the CompactDeposit witness hash.
     * @param calldataOffset The offset of the CompactDeposit calldata.
     * @return witnessHash   The derived CompactDeposit witness hash.
     */
    function deriveCompactDepositWitnessHash(uint256 calldataOffset) internal pure returns (bytes32 witnessHash) {
        assembly ("memory-safe") {
            // Retrieve the free memory pointer; memory will be left dirtied.
            let m := mload(0x40)

            // Prepare the initial fragment of the witness typestring.
            mstore(m, PERMIT2_DEPOSIT_WITNESS_FRAGMENT_HASH)

            // Copy allocator, resetPeriod, scope, & recipient directly from calldata.
            // NOTE: none of these arguments are sanitized; the assumption is that they have to
            // match the signed values anyway, so *should* be fine not to sanitize them but could
            // optionally check that there are no dirty upper bits on any of them.
            calldatacopy(add(m, 0x20), calldataOffset, 0x80) 
            // offset of 0xa4 = 164 bytes
            // length of 0x80 = 128 bytes

            // Derive the CompactDeposit witness hash from the prepared data.
            witnessHash := keccak256(m, 0xa0) // length of 0xa0 = 160 bytes
            // [witness type hash - 32 bytes][calldata copy - 128 bytes]

            // Example calldata to prove locations:
            //
            // 0x10d82672| 4 bytes
            // 0...0c36442b4a4522e871399cd717abdd847ab11fe88| 32 bytes token        
            // 0...00000000000000000000000000000000000000001| 32 bytes amount       
            // 0...00000000000000000000000000000000000000002| 32 bytes nonce        
            // 0...00000000000000000000000000000000000000003| 32 bytes deadline     
            // 0...0c36442b4a4522e871399cd717abdd847ab11fe88| 32 bytes depositor    
            // 0...0c36442b4a4522e871399cd717abdd847ab11fe88| 32 bytes allocator    <- offset of calldata
            // 0...00000000000000000000000000000000000000004| 32 bytes resetPeriod  
            // 0...00000000000000000000000000000000000000001| 32 bytes scope        
            // 0...0c36442b4a4522e871399cd717abdd847ab11fe88| 32 bytes recipient    <- length of calldatacopy
            // 0...00000000000000000000000000000000000000140| 32 bytes signature offset
            // 0...00000000000000000000000000000000000000002| 32 bytes signature length
            // 12340000000000000000000000000000000000000...0| 32 bytes signature data
        }
    }

    /**
     * @notice Internal pure function for inserting the CompactDeposit typestring
     * (used for deposits that do not involve a compact registration) into memory.
     * @param memoryLocation The memory pointer to the start of the typestring.
     */
    function insertCompactDepositTypestring(uint256 memoryLocation) internal pure {
        assembly ("memory-safe") {
            // Store the length (150 bytes) of the typestring.
            mstore(memoryLocation, 0x96)

            // Write the data for the typestring.
            mstore(add(memoryLocation, 0x20), COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_ONE) // offset of 32 bytes
            mstore(add(memoryLocation, 0x40), COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_TWO) // offset of 64 bytes
            mstore(add(memoryLocation, 0x60), COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_THREE) // offset of 96 bytes
            mstore(add(memoryLocation, 0x96), COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_FIVE) // offset of 150 bytes (length only 22 bytes), so first 10 bytes are empty
            mstore(add(memoryLocation, 0x80), COMPACT_DEPOSIT_TYPESTRING_FRAGMENT_FOUR) // offset of 128 bytes (overrides first 10 empty bytes of fragment 5)
        }
    }
}
