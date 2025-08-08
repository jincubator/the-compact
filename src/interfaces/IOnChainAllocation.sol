// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IAllocator } from "./IAllocator.sol";
import { Lock } from "../types/EIP712Types.sol";

interface IOnChainAllocation is IAllocator {
    /**
     * @notice Allocate tokens for a given sponsor.
     * @dev The implementation must ensure the users intentions are met by either verifying the signature
     *      or by ensuring the claimHash is directly registered with the compact.
     * @param sponsor The account to source the tokens from.
     * @param commitments The commitments to allocate.
     * @param arbiter The account tasked with verifying and submitting the claim.
     * @param expires The time at which the claim expires.
     * @param typehash The typehash of the claim.
     * @param witness The witness of the claim.
     * @param signature The signature of the claim.
     * @return claimHash The claim hash.
     * @return claimNonce The claim nonce.
     */
    function allocateFor(
        address sponsor,
        Lock[] calldata commitments,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata signature
    ) external returns (bytes32 claimHash, uint256 claimNonce);

    /**
     * @notice Request a nonce for a given sponsor.
     * @dev Returns the next valid nonce. It is only guaranteed that the nonce is valid within the same transaction.
     * @param sponsor The account the nonce is scoped to.
     * @return The nonce.
     */
    function requestNonce(address sponsor) external view returns (uint256);
}
