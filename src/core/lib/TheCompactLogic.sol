// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { IAllocator } from "../../interfaces/IAllocator.sol";
import { ITheCompactCore } from "../../interfaces/ITheCompactCore.sol";
import { ITheCompactMultiChain } from "../../interfaces/ITheCompactMultiChain.sol";
import { IdLib } from "../../lib/IdLib.sol";
import { Scope } from "../../types/Scope.sol";
import { ResetPeriod } from "../../types/ResetPeriod.sol";
import { Errors } from "./Errors.sol";

contract TheCompactLogic {
    using SafeTransferLib for address;

    string private constant _NAME = "The Compact";
    string private constant _VERSION = "0";
    bytes32 immutable _DOMAIN_SEPARATOR;

    // Storage scope for active registrations:
    // slot: keccak256(_ACTIVE_REGISTRATIONS_SCOPE ++ sponsor ++ claimHash ++ typehash) => expires.
    uint256 private constant _ACTIVE_REGISTRATIONS_SCOPE = 0x68a30dd0;
    uint32 private constant _MAX_REGISTRATION_EXPIRATION = 30 days;

    // keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Allocation[] inputs)")
    bytes32 private constant _COMPACT_TYPEHASH = 0xe7d6f4bedb5bc0105639a581bf5c24bb987ae1e1ecabc848d191d6ac36a59970;

    // keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Allocation[] inputs)EnhancedCompact(Compact compact,uint256 chainId)MultiChainCompact(EnhancedCompact[])")
    bytes32 private constant _MULTICHAIN_COMPACT_TYPEHASH = 0x4527c6867b5e06d14c0c8048cabe293f468c8ce4d78c2cdbaf193934751a96f0;

    // keccak256("Transfer(address from,address[] to,uint256[] id,uint256[] amount,uint256 nonce,uint256 expires)")
    bytes32 private constant _TRANSFER_TYPEHASH = 0x6d44c9455c8398fa551f6b1e552d67be7e70cf294bbb32590a4baf18180519e6;

    // keccak256("Permit(address owner,address spender,uint256 id,uint256 value,uint256 nonce,uint256 deadline)")
    bytes32 private constant _PERMIT_TYPEHASH = 0x41b82e2b5a0c36576b0cbe551120f192388f4a0e73168b730f27a8a467e1f79f;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 private constant _SIGNATURE_SELECTOR = 0x1626ba7e;

    // bytes4(keccak256("attest(address,address,address,uint256,uint256)"))
    bytes4 private constant _ATTEST_SELECTOR = 0x1a808f91;

    // bytes4(keccak256("attest(address,address,address[],uint256[],uint256[],uint256,uint256,bytes)"))
    bytes4 private constant _ATTEST_BATCH_SELECTOR = 0x9da23c98;

    // Storage slot seed for ERC6909 state, used in computing balance slots.
    uint256 private constant _ERC6909_MASTER_SLOT_SEED = 0xedcaa89a82293940;

    // keccak256(bytes("Transfer(address,address,address,uint256,uint256)")).
    uint256 private constant _TRANSFER_EVENT_SIGNATURE = 0x1b3d7edb2e9c0b0e7c525b20aaaef0f5940d2ed71663c7d39266ecafac728859;

    mapping(address sponsor => uint256 currentNonce) private _permit2Nonces;
    mapping(address sponsor => mapping(uint256 nonce => bool consumed)) private _claimNonces;
    mapping(address sponsor => mapping(uint256 id => uint256 timestamp)) private _forceWithdrawalStart;

    constructor() {
        bytes32 compactEIP712DomainHash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        _DOMAIN_SEPARATOR = keccak256(abi.encode(compactEIP712DomainHash, keccak256(bytes(_NAME)), keccak256(bytes(_VERSION)), block.chainid, address(this)));
    }


    function _deposit(address token, uint256 amount, address allocator, Scope scope, ResetPeriod resetPeriod, address recipient) internal returns (uint256 id) {
        id = IdLib.toIdIfRegistered(token, scope, resetPeriod, allocator);
        _addBalance(recipient, id, amount, true);
    }

    // @dev Fee on transfer tokens are not supported, amount received will not align with the amount in the compact
    function _depositAllInputs(ITheCompactCore.Compact memory compact) internal {
        uint256 length = compact.inputs.length;
        uint256 nativeAmount = msg.value;
        for(uint256 i = 0; i < length; ++i) {
            address token = IdLib.toToken(compact.inputs[i].id);
            uint256 amount = compact.inputs[i].amount;
            if(token == address(0)) {
                // native token
                if(nativeAmount < amount) {
                    revert Errors.InvalidValue();
                }
                nativeAmount -= amount;
            } else {
                uint256 received = _collect(token, amount, msg.sender);
                if(received != amount) {
                    revert Errors.InvalidAmount(received, amount);
                }
            }
            _deposit(token, amount, IdLib.toAllocator(compact.inputs[i].id), IdLib.toScope(compact.inputs[i].id), IdLib.toResetPeriod(compact.inputs[i].id), compact.sponsor);
        }
    }

    function _collect(address token, uint256 amount, address from) internal returns (uint256 amountCollected) {
        // TODO: Implement reentrancy guard
        
        if(token == address(0)) {
            revert Errors.InvalidToken();
        }
        uint256 initialBalance = token.balanceOf(address(this));
        // transfer tokens to this contract
        token.safeTransferFrom(from, address(this), amount);
        uint256 finalBalance = token.balanceOf(address(this));
        if (initialBalance >= finalBalance) {
            revert Errors.InvalidBalanceChange(initialBalance, finalBalance);
        }
        return finalBalance - initialBalance;
    }

    function _distribute(uint256 id, uint256 amount, address to) internal {
        // TODO: Implement reentrancy guard

        address token = IdLib.toToken(id);
        if(token == address(0)) {
            payable(to).transfer(amount);
        } else {
            token.safeTransfer(to, amount);
        }
    }

    function _register(address sponsor, bytes32 digest, uint256 expires) internal {
        // Must have ensured the caller is allowed to register
        bytes32 slot = keccak256(abi.encode(_ACTIVE_REGISTRATIONS_SCOPE, sponsor, digest));
        uint256 currentExpiration;
        assembly ("memory-safe") {
            currentExpiration := sload(slot)
        }
        if(currentExpiration != 0) {
            revert Errors.AlreadyRegistered(sponsor, digest);
        }
        if(expires < block.timestamp || expires > block.timestamp + _MAX_REGISTRATION_EXPIRATION) {
            revert Errors.InvalidRegistrationDuration(expires);
        }
        assembly ("memory-safe") {
            sstore(slot, expires)
        }
    }

    function _verifyMultiChain(ITheCompactMultiChain.EnhancedCompact[] calldata compacts) internal view returns (ITheCompactCore.Compact memory compact, uint256 index) {
        // enforces the compacts are from the same sponsor and have the same expiration
        address expectedSponsor = compacts[0].compact.sponsor;
        uint256 expectedExpiration = compacts[0].compact.expires;
        for(uint256 i = 0; i < compacts.length; ++i) {
            if(compacts[i].compact.sponsor != expectedSponsor) {
                revert Errors.NotSponsor(msg.sender, compacts[i].compact.sponsor);
            }
            if(compacts[i].compact.expires != expectedExpiration) {
                revert Errors.InvalidExpiration(compacts[i].compact.expires);
            }
            // Find the compact for the current chain and ensure it is only one
            if(compacts[i].chainId == block.chainid) {
                if(compact.sponsor != address(0)) {
                    revert Errors.InvalidMultiChainCompact();
                }
                compact = compacts[i].compact;
                index = i;
                if(msg.sender != compact.arbiter) {
                    revert Errors.NotArbiter(msg.sender, compact.arbiter);
                }
            }
        }
        if(compact.sponsor == address(0)) {
            // No compact found for the current chain
            revert Errors.InvalidMultiChainCompact();
        }
        return (compact, index);
    }

    function _verifyClaim(ITheCompactCore.Claim memory claim_) internal view returns (address allocator, ITheCompactCore.Compact memory compact) {
        if(msg.sender != claim_.compact.arbiter) {
            revert Errors.NotArbiter(msg.sender, claim_.compact.arbiter);
        }
        if(claim_.compact.expires < block.timestamp) {
            revert Errors.InvalidExpiration(claim_.compact.expires);
        }
        compact = claim_.compact;
        allocator = IdLib.toAllocator(claim_.compact.inputs[0].id);
        uint256 length = compact.inputs.length;
        for(uint256 i = 0; i < length; ++i) {
            // If the last bit is set, the recipient was unknown and the arbiter is responsible for setting the recipient
            if(_lastBitIsSet(compact.inputs[i].recipient)) {
                // Remove the recipient from the compact, because it was not signed for by the sponsor and allocator
                compact.inputs[i].recipient = "";
            }
            // Ensure all inputs are from the same allocator
            if(allocator != IdLib.toAllocator(compact.inputs[i].id)) {
                revert Errors.AllocatorMismatch(allocator, IdLib.toAllocator(compact.inputs[i].id));
            }
        }
        return (allocator, compact);
    }

    function _verifyEnhancedClaim(ITheCompactMultiChain.EnhancedClaim calldata multiClaim, uint256 index) internal view returns (address allocator, ITheCompactCore.Compact memory compact_) {
        ITheCompactCore.Claim memory claim = ITheCompactCore.Claim({
            compact: multiClaim.compacts[index].compact,
            typeString: multiClaim.typeString,
            witness: multiClaim.witness,
            allocatorSignature: multiClaim.allocatorSignature,
            sponsorSignature: multiClaim.sponsorSignature
        });
        (allocator, compact_) = _verifyClaim(claim);
        return (allocator, compact_);
    }

    function _verifySignatures(bytes32 sponsorDigest, address sponsor, bytes calldata sponsorSignature, bytes32 allocatorDigest, address allocator, bytes calldata allocatorSignature) internal view {
        // Check if the digest was registered
        bytes32 slot = keccak256(abi.encode(_ACTIVE_REGISTRATIONS_SCOPE, sponsor, sponsorDigest));
        uint256 currentExpiration;
        assembly ("memory-safe") {
            currentExpiration := sload(slot)
        }
        if(currentExpiration < block.timestamp) {
            // This means no registration was found for the sponsor, since if the claim expiration is in the past the function would already have reverted.
            if(!SignatureCheckerLib.isValidSignatureNowCalldata(sponsor, sponsorDigest, sponsorSignature)) {
                revert Errors.InvalidSignature(sponsor, sponsorSignature);
            }
        }
        if(!SignatureCheckerLib.isValidSignatureNowCalldata(allocator, allocatorDigest, allocatorSignature)) {
            if(IAllocator(allocator).isValidSignature(allocatorDigest, allocatorSignature) != _SIGNATURE_SELECTOR) {
                revert Errors.InvalidSignature(allocator, allocatorSignature);
            }
        }
    }

    function _checkPermit(
        address owner,
        address spender,
        uint256 id,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    ) public virtual {
        if (block.timestamp > deadline) {
            revert Errors.InvalidExpiration(deadline);
        }

        bytes32 hash = _computePermitHash(owner, spender, id, value, _permit2Nonces[owner]++, deadline);
        if(!SignatureCheckerLib.isValidSignatureNowCalldata(spender, hash, signature)) {
            revert Errors.InvalidSignature(spender, signature);
        }
    }

    function _changeForceWithdrawalStart(uint256 id, bool enable) internal returns (uint256) {
        if(enable) {
            uint256 currentTimestamp = _forceWithdrawalStart[msg.sender][id];
            if(currentTimestamp == 0) {
                uint256 resetTimestamp = block.timestamp + IdLib.toSeconds(IdLib.toResetPeriod(id));
                _forceWithdrawalStart[msg.sender][id] = resetTimestamp;
                return resetTimestamp;
            }
            return currentTimestamp;
        }
        // disable forced withdrawal
        delete _forceWithdrawalStart[msg.sender][id];
        return 0;
    }

    function _checkForceWithdrawalStart(uint256 id) internal view {
        uint256 currentTimestamp = _forceWithdrawalStart[msg.sender][id];
        if(currentTimestamp == 0 || currentTimestamp > block.timestamp) {
            revert Errors.ForcedWithdrawalNotActive(id, currentTimestamp);
        }
    }
    
    function _getForceWithdrawalStart(address sponsor, uint256 id) internal view returns (uint256) {
        return _forceWithdrawalStart[sponsor][id];
    }

    function _checkNonce(address allocator, uint256 nonce) internal view {
        if(_nonceConsumed(allocator, nonce)) {
            revert Errors.NonceAlreadyConsumed(nonce);
        }
    }

    function _checkNonce(uint256 id, uint256 nonce) internal view returns (address allocator) {
        allocator = IdLib.toAllocator(id);
        if(_nonceConsumed(allocator, nonce)) {
            revert Errors.NonceAlreadyConsumed(nonce);
        }
    }

    function _consumeNonce(address allocator, uint256 nonce) internal {
        _claimNonces[allocator][nonce] = true;
    }

    function _nonceConsumed(address allocator, uint256 nonce) internal view returns (bool) {
        return _claimNonces[allocator][nonce];
    }

    function _getPermit2Nonce(address owner) internal view returns (uint256) {
        return _permit2Nonces[owner];
    }

    // @dev Since there is no nonce, a single attestation can only be verified by an on chain allocator.
    function _ensureAttested(address from, address to, uint256 id, uint256 amount) internal {
        // Derive the allocator address from the supplied id.
        address allocator = IdLib.toAllocator(id);
        // Ensure the allocator attests the transfer.
        if( IAllocator(allocator).attest(msg.sender, from, to, id, amount) != _ATTEST_SELECTOR) {
            revert Errors.AllocatorDenied(allocator);
        }
    }

    function _ensureBatchAttested(address caller, address from, ITheCompactCore.Transfer calldata transfer, bytes calldata allocatorSignature) internal returns (uint256 length) {
        address expectedAllocator = IdLib.toAllocator(transfer.recipients[0].id);
        // Ensure the allocator attests the transfers.
        length = transfer.recipients.length;
        address[] memory to = new address[](length);
        uint256[] memory id = new uint256[](length);
        uint256[] memory amount = new uint256[](length);
        for(uint256 i = 0; i < length; ++i) {
            address allocator = IdLib.toAllocator(id[i]);
            if(expectedAllocator != allocator) {
                revert Errors.AllocatorMismatch(expectedAllocator, allocator);
            }
            to[i] = _castToAddress(transfer.recipients[i].recipient);
            id[i] = transfer.recipients[i].id;
            amount[i] = transfer.recipients[i].amount;
        }

        bytes32 digest = _transferDigest(from, to, id, amount, transfer.nonce, transfer.expires);
        if(!SignatureCheckerLib.isValidSignatureNowCalldata(expectedAllocator, digest, allocatorSignature)) {
            if( IAllocator(expectedAllocator).attest(caller, from, to, id, amount, transfer.nonce, transfer.expires, allocatorSignature) != _ATTEST_BATCH_SELECTOR) {
                revert Errors.AllocatorDenied(expectedAllocator);
            }        
        }
    }

    // @notice Reverts if the caller does not have approval. Reduces the allowance by the amount.
    // @dev Copied from ERC6909.sol _transfer
    function _checkApproval(address by, address from, uint256 id, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            let bitmaskAddress := 0xffffffffffffffffffffffffffffffffffffffff
            // Compute the operator slot and load its value.
            mstore(0x34, _ERC6909_MASTER_SLOT_SEED)
            mstore(0x28, from)
            // If `by` is not the zero address.
            if and(bitmaskAddress, by) {
                mstore(0x14, by)
                // Check if the `by` is an operator.
                if iszero(sload(keccak256(0x20, 0x34))) {
                    // Compute the allowance slot and load its value.
                    mstore(0x00, id)
                    let allowanceSlot := keccak256(0x00, 0x54)
                    let allowance_ := sload(allowanceSlot)
                    // If the allowance is not the maximum uint256 value.
                    if add(allowance_, 1) {
                        // Revert if the amount to be transferred exceeds the allowance.
                        if gt(amount, allowance_) {
                            mstore(0x00, 0xdeda9030) // `InsufficientPermission()`.
                            revert(0x1c, 0x04)
                        }
                        // Subtract and store the updated allowance.
                        sstore(allowanceSlot, sub(allowance_, amount))
                    }
                }
            }
        }
    }

    function _compactDigest(ITheCompactCore.Compact memory compact) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                _DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        _COMPACT_TYPEHASH,
                        compact.arbiter,
                        compact.sponsor,
                        compact.nonce,
                        compact.expires,
                        compact.inputs
                    )
                )
            )
        );
    }

    function _compactDigestWitness(ITheCompactCore.Compact memory compact, bytes32 witness, string calldata typeString) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                _DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        keccak256(bytes(typeString)),
                        compact.arbiter,
                        compact.sponsor,
                        compact.nonce,
                        compact.expires,
                        compact.inputs,
                        witness
                    )
                )
            )
        );
    }

    function _compactDigestQualification(bytes32 sponsorSignedDigest, bytes32 qualification, string calldata qualificationTypeString) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                _DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        keccak256(bytes(qualificationTypeString)),
                        sponsorSignedDigest,
                        qualification
                    )
                )
            )
        );
    }

    function _compactDigestMultiChain(ITheCompactMultiChain.EnhancedCompact[] memory compacts) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                _DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        _MULTICHAIN_COMPACT_TYPEHASH,
                        compacts
                    )
                )
            )
        );
    }

    function _compactDigestWithWitnessMultiChain(ITheCompactMultiChain.EnhancedCompact[] memory compacts, bytes32 witness, string calldata typeString) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                _DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        keccak256(bytes(typeString)),
                        compacts,
                        witness
                    )
                )
            )
        );
    }

    function _transferDigest(address from, address[] memory to, uint256[] memory id, uint256[] memory amount, uint256 nonce, uint256 expires) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                _DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        _TRANSFER_TYPEHASH,
                        from,
                        to,
                        id,
                        amount,
                        nonce,
                        expires
                    )
                )
            )
        );
    }

    function _computePermitHash(address owner, address spender, uint256 id, uint256 value, uint256 nonce, uint256 deadline) internal view returns (bytes32) {
                return keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                _DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        _PERMIT_TYPEHASH,
                        owner,
                        spender,
                        value,
                        id,
                        nonce,
                        deadline
                    )
                )
            )
        );
    }


    // @dev Adapts the ERC6909 balance without requiring an approval
    // @dev Skips the _beforeTokenTransfer and _afterTokenTransfer hooks
    function _rebalance(address from, address to, uint256 id, uint256 amount, bool triggerEvent) internal {
        _removeBalance(from, id, amount, false);
        _addBalance(to, id, amount, false);
        if(triggerEvent) {
            assembly ("memory-safe") {
                // Emit the {Transfer} event.
                mstore(0x00, caller())
                mstore(0x20, amount)
                log4(0x00, 0x40, _TRANSFER_EVENT_SIGNATURE, caller(), shr(96, shl(96, to)), id)
            }
        }
    }

    function _addBalance(address to, uint256 id, uint256 amount, bool triggerEvent) internal {
        assembly ("memory-safe") {
            // Compute the recipient's balance slot using the master slot seed.
            mstore(0x20, _ERC6909_MASTER_SLOT_SEED) // length of 64 bits
            mstore(0x14, to) // Length of 160 bits
            mstore(0x00, id) // length of 256 bits
            //           -----------SLOT 1-----------   -----------SLOT 2-----------
            // master:  |        - 256 bits  -         | [0000000000000000000][--64 bits--]
            // to:      |    - 160 bits  -     [[0000] | [---160 bits---]]
            // id:      | [---------256 bits---------] |        - 256 bits  -

            let toBalanceSlot := keccak256(0x00, 0x40)

            // Load current balance and compute new balance.
            let toBalanceBefore := sload(toBalanceSlot)
            let toBalanceAfter := add(toBalanceBefore, amount)

            // Revert on balance overflow.
            if lt(toBalanceAfter, toBalanceBefore) {
                mstore(0x00, 0x89560ca1) // `BalanceOverflow()`.
                revert(0x1c, 0x04)
            }

            // Store the updated balance.
            sstore(toBalanceSlot, toBalanceAfter)

            if triggerEvent {
                // Emit the Transfer event:
                // - topic1: Transfer event signature
                // - topic2: address(0) signifying a mint
                // - topic3: recipient address (sanitized)
                // - topic4: token id
                // - data: [caller, amount]
                mstore(0x00, caller())
                mstore(0x20, amount)
                log4(0, 0x40, _TRANSFER_EVENT_SIGNATURE, 0, shr(0x60, shl(0x60, to)), id)
            }
        }
    }

    function _removeBalance(address from, uint256 id, uint256 amount, bool triggerEvent) internal {
        assembly ("memory-safe") {
            // Compute the sender's balance slot using the master slot seed.
            mstore(0x20, _ERC6909_MASTER_SLOT_SEED)
            mstore(0x14, from)
            mstore(0x00, id)
            let fromBalanceSlot := keccak256(0x00, 0x40)

            // Load from sender's current balance.
            let fromBalance := sload(fromBalanceSlot)

            // Revert if insufficient balance.
            if gt(amount, fromBalance) {
                mstore(0x00, 0xf4d678b8) // `InsufficientBalance()`.
                revert(0x1c, 0x04)
            }

            // Subtract from current balance and store the updated balance.
            sstore(fromBalanceSlot, sub(fromBalance, amount))

            if triggerEvent {
                // Emit the Transfer event:
                //  - topic1: Transfer event signature
                //  - topic2: sender address (sanitized)
                //  - topic3: address(0) signifying a burn
                //  - topic4: token id
                //  - data: [caller, amount]
                mstore(0x00, caller())
                mstore(0x20, amount)
                log4(0x00, 0x40, _TRANSFER_EVENT_SIGNATURE, shr(0x60, shl(0x60, from)), 0, id)
            }
        }
    }

    function _castToAddress(bytes32 address_) internal pure returns (address output_) {
        assembly ("memory-safe") {
            output_ := shr(96, shl(96, address_))
        }
    }

    function _sanitizeAddress(address address_) internal pure returns (address output_) {
        assembly ("memory-safe") {
            output_ := shr(96, shl(96, address_))
        }
    }

    function _lastBitIsSet(bytes32 value) internal pure returns (bool) {
        // Shift right 255 bits and check if 1
        return uint256(value) >> 255 == 1;

        // To mark a receiver as unknown to the sponsor and therefore not part of the signed data, the last bit of the receiver must be set to 1 by the arbiter.
        // This is how the bytes32 receiver is structured in a claim:
        // [           1 bit         ][                  95 bits                ][                      160 bits                          ]
        // [ indicate empty receiver ][       available for other features      ][                      receiver                          ]
    }

    function _markDelegation(bytes32 receiver, address caller_) internal pure returns (bytes32) {
        // To mark the delegation, the first 95 bits of the callers address will be stored in the receiver
        // This leaves room for the first bit to be set by the arbiter to indicate the recipient was not signed for by the sponsor
        // This is how the bytes32 receiver is structured in a claim:
        // [           1 bit         ][                  95 bits                ][                      160 bits                          ]
        // [ indicate empty receiver ][ last 95 bits of the registering address ][                      receiver                          ]

        assembly ("memory-safe") {
            receiver := shr(96, shl(96, receiver))
            caller_ := shr(1, shl(160, caller_))
            receiver := or(receiver, caller_)
        }
        return receiver;
    }
}
