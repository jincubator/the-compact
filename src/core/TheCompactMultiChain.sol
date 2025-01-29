// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { IdLib } from "../lib/IdLib.sol";
import { Scope } from "../types/Scope.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Deposit } from "./lib/Deposit.sol";
import { ITheCompactCore } from "../interfaces/ITheCompactCore.sol";
import { ITheCompactMultiChain } from "src/interfaces/ITheCompactMultiChain.sol";
import { IAllocator } from "../interfaces/IAllocator.sol";
import { ITheCompactService } from "../interfaces/ITheCompactService.sol";
import { Errors } from "./lib/Errors.sol";

contract TheCompactMultiChain is Deposit {


    // function claimWithQualification(ITheCompactCore.Claim calldata claim_, bytes32 qualificationHash, string calldata qualificationTypeString, bool withdraw) external returns (bool) {
    //     (address allocator, ITheCompactCore.Compact memory compact) = _verifyClaim(claim_);
    //     _checkNonce(allocator, claim_.compact.nonce);
    //     bytes32 digest = claim_.witness == bytes32(0) ? _compactDigest(compact) : _compactDigestWitness(compact, claim_.witness, claim_.typeString);
    //     bytes32 allocatorDigest = _compactDigestQualification(digest, qualificationHash, qualificationTypeString);
    //     _verifySignatures(digest, claim_.compact.sponsor, claim_.sponsorSignature, allocatorDigest, allocator, claim_.allocatorSignature);
    //     // The allocator has successfully attested to the withdrawal. If the nonce is not 0, it must be consumed
    //     if(claim_.compact.nonce != 0) {
    //         // If the nonce is 0, it must be an on chain allocator that does not require a nonce to attest.
    //         _consumeNonce(allocator, claim_.compact.nonce);
    //     }
    //     uint256 length = claim_.compact.inputs.length;
    //     for(uint256 i = 0; i < length; ++i) {
    //         if(withdraw) {
    //             _burn(claim_.compact.sponsor, claim_.compact.inputs[i].id, claim_.compact.inputs[i].amount);
    //             _distribute(claim_.compact.inputs[i].id, claim_.compact.inputs[i].amount, _castToAddress(claim_.compact.inputs[i].recipient));
    //         } else {
    //             _rebalance(claim_.compact.sponsor, _castToAddress(claim_.compact.inputs[i].recipient), claim_.compact.inputs[i].id, claim_.compact.inputs[i].amount, false);
    //             // TODO: add event
    //         }
    //     }
    //     return true;
    // }

}