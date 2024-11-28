// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ResetPeriod } from "../types/ResetPeriod.sol";

import { EfficiencyLib } from "./EfficiencyLib.sol";
import { IdLib } from "./IdLib.sol";

/**
 * @title RegistrationLib
 * @notice Library contract implementing logic for registering compact claim hashes
 * and typehashes and querying for whether given claim hashes and typehashes have
 * been registered.
 */
library RegistrationLib {
    using RegistrationLib for address;
    using EfficiencyLib for uint256;
    using IdLib for ResetPeriod;

    // keccak256(bytes("CompactRegistered(address,bytes32,bytes32,uint256)")).
    uint256 private constant _COMPACT_REGISTERED_SIGNATURE = 0xf78a2f33ff80ef4391f7449c748dc2d577a62cd645108f4f4069f4a7e0635b6a;

    // Storage scope for active registrations:
    // slot: keccak256(_ACTIVE_REGISTRATIONS_SCOPE ++ sponsor ++ claimHash ++ typehash) => expires.
    uint256 private constant _ACTIVE_REGISTRATIONS_SCOPE = 0x68a30dd0;

    /**
     * @notice Internal function for registering a claim hash with a specific duration. The
     * claim hash and its associated typehash will remain valid until the specified duration
     * has elapsed. Reverts if the duration would result in an expiration earlier than an
     * existing registration or if it exceeds 30 days.
     * @param sponsor   The account registering the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @param duration  The duration in seconds for which the registration remains valid.
     */
    function registerCompactWithSpecificDuration(address sponsor, bytes32 claimHash, bytes32 typehash, uint256 duration) internal {
        assembly ("memory-safe") {
            // Retrieve the current free memory pointer.
            let m := mload(0x40)

            // Pack data for deriving active registration storage slot.
            mstore(add(m, 0x14), sponsor) // 160 bits length at 160 bits + 96 empty bits  = 256-416 bits
            mstore(m, _ACTIVE_REGISTRATIONS_SCOPE) // 32 bits  length at 0 bits   + 224 empty bits = 224-256 bits
            mstore(add(m, 0x34), claimHash) // 256 bits length at 416 bits + 0 empty bits   = 416-672 bits
            mstore(add(m, 0x54), typehash) // 256 bits length at 672 bits + 0 empty bits   = 672-928 bits

            // Derive and load active registration storage slot to get current expiration.
            let cutoffSlot := keccak256(add(m, 0x1c), 0x58) // hash bits 224-928

            // LETS MOVE THE SLOT CREATION CODE TO ANOTHER INTERNAL FUNCTION, SINCE IT IS USED IN MULTIPLE PLACES.

            // Compute new expiration based on current timestamp and supplied duration.
            let expires := add(timestamp(), duration)

            // Ensure new expiration is not earlier than current and duration does not exceed 30 days.
            if or(lt(expires, sload(cutoffSlot)), gt(duration, 0x278d00)) {
                // LETS MAYBE MOVE THE HARDCODED 30 days max EXPIRATION TO A CONSTANT FOR EASY ADAPTATION?
                // revert InvalidRegistrationDuration(uint256 duration)
                mstore(0, 0x1f9a96f4)
                mstore(0x20, duration)
                revert(0x1c, 0x24)
            }

            // WHY DO WE NOT LIMIT THE DURATION TO THE RESET PERIOD OF THE TOKEN? THIS WAY, EVERYONE KNOWS THAT A REGISTERED CLAIM IS ACTUALLY VALID.

            // Store new expiration in active registration storage slot.
            sstore(cutoffSlot, expires)

            // Emit the CompactRegistered event:
            //  - topic1: CompactRegistered event signature
            //  - topic2: sponsor address (sanitized)
            //  - data: [claimHash, typehash, expires]
            mstore(add(m, 0x74), expires)
            log2(add(m, 0x34), 0x60, _COMPACT_REGISTERED_SIGNATURE, shr(0x60, shl(0x60, sponsor)))
        }

        // // SOLIDITY CODE:
        // // gas efficiency assembly code: 25_259 gas
        // // gas efficiency solidity code: 26_537 gas
        // bytes32 cutoffSlot = keccak256(abi.encodePacked(bytes4(bytes32(_ACTIVE_REGISTRATIONS_SCOPE)), sponsor, claimHash, typehash));
        // uint256 currentExpiration;
        // assembly ("memory-safe") {
        //     currentExpiration := sload(cutoffSlot)
        // }
        // uint256 expires = block.timestamp + duration;
        // if (expires < currentExpiration || duration > 30 days) {
        //     revert InvalidRegistrationDuration(duration);
        // }
        // assembly ("memory-safe") {
        //     sstore(cutoffSlot, expires)
        // }
        // emit CompactRegistered(sponsor, claimHash, typehash, expires);
    }

    /**
     * @notice Internal function for registering a claim hash with a duration specified as a
     * ResetPeriod enum value.
     * @param sponsor   The account registering the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @param duration  The ResetPeriod enum value specifying the registration duration.
     */
    function registerCompact(address sponsor, bytes32 claimHash, bytes32 typehash, ResetPeriod duration) internal {
        sponsor.registerCompactWithSpecificDuration(claimHash, typehash, duration.toSeconds());
    }

    /**
     * @notice Internal function for registering a claim hash with the default duration (10
     * minutes) using the caller as the sponsor.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     */
    function registerAsCallerWithDefaultDuration(bytes32 claimHash, bytes32 typehash) internal {
        msg.sender.registerCompactWithSpecificDuration(claimHash, typehash, uint256(0x258).asStubborn()); // LETS MAYBE MOVE THE HARDCODED 10 MINUTES DEFAULT TO A CONSTANT FOR EASY ADAPTATION?
    }

    /**
     * @notice Internal function for registering multiple claim hashes in a single call. All
     * claim hashes will be registered with the same duration using the caller as the sponsor.
     * @param claimHashesAndTypehashes Array of [claimHash, typehash] pairs for registration.
     * @param duration                 The duration for which the claim hashes remain valid.
     * @return                         Whether all claim hashes were successfully registered.
     */
    function registerBatchAsCaller(bytes32[2][] calldata claimHashesAndTypehashes, uint256 duration) internal returns (bool) {
        unchecked {
            // Retrieve the total number of claim hashes and typehashes to register.
            uint256 totalClaimHashes = claimHashesAndTypehashes.length;

            // Iterate over each pair of claim hashes and typehashes.
            for (uint256 i = 0; i < totalClaimHashes; ++i) {
                // Retrieve the claim hash and typehash from calldata.
                bytes32[2] calldata claimHashAndTypehash = claimHashesAndTypehashes[i];

                // Register the compact as the caller with the specified duration.
                msg.sender.registerCompactWithSpecificDuration(claimHashAndTypehash[0], claimHashAndTypehash[1], duration);
            }
        }

        return true;
    }

    /**
     * @notice Internal view function for retrieving the expiration timestamp of a
     * registration.
     * @param sponsor   The account that registered the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @return expires  The timestamp at which the registration expires.
     */
    function toRegistrationExpiration(address sponsor, bytes32 claimHash, bytes32 typehash) internal view returns (uint256 expires) {
        assembly ("memory-safe") {
            // Retrieve the current free memory pointer.
            let m := mload(0x40)

            // Pack data for deriving active registration storage slot.
            mstore(add(m, 0x14), sponsor)
            mstore(m, _ACTIVE_REGISTRATIONS_SCOPE)
            mstore(add(m, 0x34), claimHash)
            mstore(add(m, 0x54), typehash)

            // LETS MOVE THE SLOT CREATION CODE TO ANOTHER INTERNAL FUNCTION, SINCE IT IS USED IN MULTIPLE PLACES.

            // Derive and load active registration storage slot to get current expiration.
            expires := sload(keccak256(add(m, 0x1c), 0x58))
        }
    }

    /**
     * @notice Internal view function for checking if a registration is inactive or expired.
     * @param sponsor   The account that registered the claim hash.
     * @param claimHash A bytes32 hash derived from the details of the compact.
     * @param typehash  The EIP-712 typehash associated with the claim hash.
     * @return          Whether the registration is inactive or has expired.
     */
    function hasNoActiveRegistration(address sponsor, bytes32 claimHash, bytes32 typehash) internal view returns (bool) {
        return sponsor.toRegistrationExpiration(claimHash, typehash) <= block.timestamp;
    }
}
