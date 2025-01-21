// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { IAllocator } from "../../interfaces/IAllocator.sol";
import { ITheCompactCore } from "../../interfaces/ITheCompactCore.sol";
import { IdLib } from "../../lib/IdLib.sol";
import { Scope } from "../../types/Scope.sol";
import { ResetPeriod } from "../../types/ResetPeriod.sol";
import { Errors } from "./Errors.sol";

contract Deposit {
    using SafeTransferLib for address;

    function _deposit(address token, uint256 amount, address allocator, Scope scope, ResetPeriod resetPeriod, address recipient) internal returns (uint256 id) {
        id = IdLib.toIdIfRegistered(token, scope, resetPeriod, allocator);
        _addBalance(recipient, id, amount, true);
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
        token.safeTransfer(to, amount);
    }

    /// TODO: Move everything below to a separate transfer contract

    // Storage scope for active registrations:
    // slot: keccak256(_ACTIVE_REGISTRATIONS_SCOPE ++ sponsor ++ claimHash ++ typehash) => expires.
    uint256 private constant _ACTIVE_REGISTRATIONS_SCOPE = 0x68a30dd0;
    uint32 private constant _MAX_EXPIRATION = 30 days;


    function _register(address caller, address sponsor, bytes32 digest, uint256 expires) internal {
        if(caller != sponsor) {
            revert Errors.NotSponsor(caller, sponsor);
        }
        bytes32 slot = keccak256(abi.encode(_ACTIVE_REGISTRATIONS_SCOPE, sponsor, digest));
        uint256 currentExpiration;
        assembly ("memory-safe") {
            currentExpiration := sload(slot)
        }
        if(currentExpiration > expires || expires > block.timestamp + _MAX_EXPIRATION) {
            revert Errors.InvalidRegistrationDuration(expires);
        }
        assembly ("memory-safe") {
            sstore(slot, expires)
        }
    }

    function _verifyClaim(ITheCompactCore.Claim calldata claim_) internal view returns (address allocator, ITheCompactCore.Compact memory compact) {
        if(msg.sender != claim_.compact.arbiter) {
            revert Errors.NotArbiter(msg.sender, claim_.compact.arbiter);
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
    }

    // abi.decode(bytes("Compact(address arbiter,address "), (bytes32))
    bytes32 constant COMPACT_TYPESTRING_FRAGMENT_ONE = 0x436f6d70616374286164647265737320617262697465722c6164647265737320;
    // abi.decode(bytes("sponsor,uint256 nonce,uint256 ex"), (bytes32))
    bytes32 constant COMPACT_TYPESTRING_FRAGMENT_TWO = 0x73706f6e736f722c75696e74323536206e6f6e63652c75696e74323536206578;
    // abi.decode(bytes("pires,uint256 id,uint256 amount)"), (bytes32))
    bytes32 constant COMPACT_TYPESTRING_FRAGMENT_THREE = 0x70697265732c75696e743235362069642c75696e7432353620616d6f756e7429;

    // bytes32 compactEIP712DomainHash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    // bytes32 domainSeparator = keccak256(abi.encode(compactEIP712DomainHash, keccak256(bytes("The Compact")), keccak256(bytes("0")), block.chainid, address(this)));
    bytes32 constant DOMAIN_SEPARATOR = 0x423efda6f5a4d5cd578a57b46b5306d04ae04f054e798cb0cd6074f08bf583ee;

    // keccak256("Compact(uint256 chainId,address arbiter,address sponsor,uint256 nonce,uint256 expires,Allocation[] inputs)");
    bytes32 constant COMPACT_TYPEHASH = 0x0fee4917c24cc0706c3f2cb7a7b89603d1fef1a7efb46bd67061fe47d0f8df1b;

    function _compactDigest(ITheCompactCore.Compact memory compact) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        COMPACT_TYPEHASH,
                        compact.chainId,
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

    function _compactDigestWitness(ITheCompactCore.Compact calldata compact, bytes32 witness, string calldata typeString) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        keccak256(bytes(typeString)),
                        compact.chainId,
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

    bytes4 constant SIGNATURE_MAGIC_VALUE = 0x1626ba7e;

    function _verifySignatures(bytes32 digest, address sponsor, bytes calldata sponsorSignature, address allocator, bytes calldata allocatorSignature) internal view {
        // Check if the digest was registered
        bytes32 slot = keccak256(abi.encode(_ACTIVE_REGISTRATIONS_SCOPE, sponsor, digest));
        uint256 currentExpiration;
        assembly ("memory-safe") {
            currentExpiration := sload(slot)
        }
        if(currentExpiration < block.timestamp) {
            if(!SignatureCheckerLib.isValidSignatureNowCalldata(sponsor, digest, sponsorSignature)) {
                revert Errors.InvalidSignature(sponsor, sponsorSignature);
            }
        }
        if(!SignatureCheckerLib.isValidSignatureNowCalldata(allocator, digest, allocatorSignature)) {
            if(IAllocator(allocator).isValidSignature(digest, allocatorSignature) != SIGNATURE_MAGIC_VALUE) {
                revert Errors.InvalidSignature(allocator, allocatorSignature);
            }
        }
    }


    // // TODO: First concept was to sort the type string structs, but likely unnecessary. Easier if User provides the full type string.
    // string constant COMPACT_TYPESTRING = "Compact(uint256 chainId,address arbiter,address sponsor,uint256 nonce,uint256 expires,Allocation[] inputs)";
    // string constant COMPACT_WITNESS_TYPESTRING = "Compact(uint256 chainId,address arbiter,address sponsor,uint256 nonce,uint256 expires,Allocation[] inputs,Witness witness)";
    // string constant ALLOCATION_TYPESTRING = "Allocation(uint256 id,uint256 amount,address recipient)";
    // string constant WITNESS_TYPESTRING_FRAGMENT_ONE = "Witness(";
    // string constant WITNESS_TYPESTRING_FRAGMENT_TWO = ")";
    // // Value of the first two bytes of the Compact type string
    // uint16 constant COMPACT_VALUE = 17263;
    // // Value of the first two bytes of the Allocation type string
    // uint16 constant ALLOCATION_VALUE = 16748;
    // // Value of the first two bytes of the Witness type string
    // uint16 constant WITNESS_VALUE = 22377;
    // function _typeHashWitness(string calldata typeString, string[] calldata structTypestrings) internal returns (bytes32) {

    //     uint16 currentValue;
    //     uint16 nextValue = ALLOCATION_VALUE;
    //     uint256 structTypestringsLength = structTypestrings.length;

    //     bytes memory currentTypestring;

    //     for(uint256 i = 0; i < structTypestringsLength; ++i) {
    //         uint16 value = _getFirstTwoBytes(structTypestrings[i]);
    //         if(value < currentValue) {
    //             revert Errors.InvalidStructTypestringOrder(structTypestrings[i]);
    //         }
    //         if(value < nextValue) {
    //             currentTypestring = abi.encodePacked(bytes(currentTypestring), structTypestrings[i]);
    //         } else if(value == nextValue) {
    //             revert Errors.InvalidStructName(structTypestrings[i]);
    //         } else if(value > nextValue) {
    //             if(nextValue == ALLOCATION_VALUE) {
    //                 currentTypestring = abi.encodePacked(bytes(currentTypestring), ALLOCATION_TYPESTRING);
    //                 nextValue = COMPACT_VALUE;
    //             } else if (nextValue == COMPACT_VALUE) {
    //                 currentTypestring = abi.encodePacked(bytes(currentTypestring), COMPACT_TYPESTRING);
    //                 nextValue = WITNESS_VALUE;
    //             } else {
    //                 currentTypestring = abi.encodePacked(bytes(currentTypestring), WITNESS_TYPESTRING_FRAGMENT_ONE);

    //             }
    //         }
    //         currentValue = value;
    //     }

    //     return keccak256(abi.encode(typeString));
    // }

    // function _getFirstTwoBytes(string calldata typeString) internal pure returns (uint16) {
    //     uint16 result;
    //     assembly ("memory-safe") {
    //         // Load first two bytes from calldata
    //         result := shr(240, calldataload(typeString.offset))
    //     }
    //     return result;
    // }


    // bytes4(keccak256("attest(address,address,address,uint256,uint256)"))
    bytes4 private constant _ATTEST_SELECTOR = 0x1a808f91;
    // bytes4(keccak256("attest(address,address,address[],uint256[],uint256[],uint256,uint256,bytes)"))
    bytes4 private constant _ATTEST_BATCH_SELECTOR = 0x9da23c98;
    // Storage slot seed for ERC6909 state, used in computing balance slots.
    uint256 private constant _ERC6909_MASTER_SLOT_SEED = 0xedcaa89a82293940;

    // keccak256(bytes("Transfer(address,address,address,uint256,uint256)")).
    uint256 private constant _TRANSFER_EVENT_SIGNATURE = 0x1b3d7edb2e9c0b0e7c525b20aaaef0f5940d2ed71663c7d39266ecafac728859;


    function _ensureAttested(address from, address to, uint256 id, uint256 amount) internal {
        // Derive the allocator address from the supplied id.
        address allocator = IdLib.toAllocator(id);
        // Ensure the allocator attests the transfer.
        if( IAllocator(allocator).attest(msg.sender, from, to, id, amount) != _ATTEST_SELECTOR) {
            revert Errors.AllocatorDenied(allocator);
        }
    }

    function _ensureBatchAttested(address caller, ITheCompactCore.Transfer calldata transfer, bytes calldata allocatorSignature) internal returns (uint256 length) {
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

        if( IAllocator(expectedAllocator).attest(caller, caller, to, id, amount, transfer.nonce, transfer.expires, allocatorSignature) != _ATTEST_BATCH_SELECTOR) {
            revert Errors.AllocatorDenied(expectedAllocator);
        }
    }

    function _castToAddress(bytes32 address_) internal pure returns (address output_) {
        assembly ("memory-safe") {
            output_ := shr(96, shl(96, address_))
        }
    }

    function _lastBitIsSet(bytes32 value) internal pure returns (bool) {
        // Shift right 255 bits and check if 1
        return uint256(value) >> 255 == 1;
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

            // SAME COMMENT AS ABOVE, LETS UNIFY THIS BALANCE / SLOT RETRIEVAL LOGIC INTO ONE INTERNAL FUNCTION.

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
}
