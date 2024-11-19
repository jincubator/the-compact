// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { ERC6909 } from "lib/solady/src/tokens/ERC6909.sol";
import { ERC6909 } from "lib/solady/src/tokens/ERC6909.sol";
import { IERC1271 } from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import { Ownable } from "openzeppelin-contracts/contracts/access/Ownable.sol";
import { Ownable2Step } from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import { ECDSA } from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import { IAllocator } from "src/interfaces/IAllocator.sol";
import { ITheCompactClaims } from "src/interfaces/ITheCompactClaims.sol";
import { ITheCompact } from "src/interfaces/ITheCompact.sol";
import { BasicClaim } from "src/types/Claims.sol";
import { Compact } from "src/types/EIP712Types.sol";

contract SimpleAllocator is Ownable2Step, IAllocator {
    struct LockedAllocation {
        uint216 amount;
        uint40 expires;
    }

    // The slot holding the current active claim, transiently. bytes32(uint256(keccak256("ActiveClaim")) - 1)
    uint256 private constant _ACTIVE_CLAIM_SLOT = 0x52878b5aadd152a1719f94d6380573e67df5b5f15153bef7af957f0c05d2a1bf;
    // The slot holding the current active claim sponsor, transiently. bytes32(uint256(keccak256("ActiveClaimSponsor")) - 1)
    uint256 private constant _ACTIVE_CLAIM_SPONSOR_SLOT = 0x5c0cba9a91a791e685f0a43b1ceba6e6670ab2d235795af4fe5350bca1423e19;
    address private immutable _COMPACT_CONTRACT;
    address private immutable _ARBITER;
    uint256 private immutable _MIN_WITHDRAWAL_DELAY;
    uint256 private immutable _MAX_WITHDRAWAL_DELAY;

    // mapping(bytes32 tokenHash => LockedAllocation allocation) private _locked;

    mapping(bytes32 tokenHash => uint256 expiration) private _claim;
    mapping(bytes32 tokenHash => uint256 amount) private _amount;
    mapping(bytes32 tokenHash => uint256 nonce) private _nonce;
    mapping(bytes32 digest => bytes32 tokenHash) private _sponsor;

    error ClaimActive(address sponsor);
    error InvalidCaller(address caller, address expected);
    error InvalidArbiter(address arbiter);
    error NonceAlreadyConsumed(uint256 nonce);
    error InsufficientBalance(address sponsor, uint256 id);
    error InvalidExpiration(uint256 expires);
    error InvalidLock(bytes32 digest, uint256 expiration);

    event Locked(address sponsor, uint256 id, uint256 amount, uint256 expires);

    constructor(address compactContract_, address arbiter_, uint256 minWithdrawalDelay_, uint256 maxWithdrawalDelay_, address owner_) Ownable(owner_) {
        _COMPACT_CONTRACT = compactContract_;
        _ARBITER = arbiter_;
        _MIN_WITHDRAWAL_DELAY = minWithdrawalDelay_;
        _MAX_WITHDRAWAL_DELAY = maxWithdrawalDelay_;
    }

    /// @dev locks all tokens of a sponsor for an id
    function lock(Compact calldata compact_) external {
        // Check msg.sender is sponsor
        if (msg.sender != compact_.sponsor) {
            revert InvalidCaller(msg.sender, compact_.sponsor);
        }
        bytes32 tokenHash = _getTokenHash(compact_.id, msg.sender);
        // Check if the claim is already active
        if (_claim[tokenHash] > block.timestamp && !ITheCompact(_COMPACT_CONTRACT).hasConsumedAllocatorNonce(_nonce[tokenHash], address(this))) {
            revert ClaimActive(compact_.sponsor);
        }
        // Check no lock is active for this sponsor
        if (_claim[tokenHash] > block.timestamp) {
            revert ClaimActive(compact_.sponsor);
        }
        // Check arbiter is valid
        if (compact_.arbiter != _ARBITER) {
            revert InvalidArbiter(compact_.arbiter);
        }
        // Check expiration is not too soon or too late
        if (compact_.expires < block.timestamp + _MIN_WITHDRAWAL_DELAY || compact_.expires > block.timestamp + _MAX_WITHDRAWAL_DELAY) {
            revert InvalidExpiration(compact_.expires);
        }
        // Check nonce is not yet consumed
        if (ITheCompact(_COMPACT_CONTRACT).hasConsumedAllocatorNonce(compact_.nonce, address(this))) {
            revert NonceAlreadyConsumed(compact_.nonce);
        }

        uint256 balance = ERC6909(_COMPACT_CONTRACT).balanceOf(msg.sender, compact_.id);
        // Check balance is enough
        if (balance < compact_.amount) {
            revert InsufficientBalance(msg.sender, compact_.id);
        }

        bytes32 digest = keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                ITheCompact(_COMPACT_CONTRACT).DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)"),
                        compact_.arbiter,
                        compact_.sponsor,
                        compact_.nonce,
                        compact_.expires,
                        compact_.id,
                        compact_.amount
                    )
                )
            )
        );

        _claim[tokenHash] = compact_.expires;
        _amount[tokenHash] = compact_.amount;
        _sponsor[digest] = tokenHash;
        _nonce[digest] = compact_.nonce;

        emit Locked(compact_.sponsor, compact_.id, compact_.amount, compact_.expires);
    }

    function attest(address operator_, address from_, address, uint256 id_, uint256 amount_) external view returns (bytes4) {
        if (msg.sender != _COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, _COMPACT_CONTRACT);
        }
        // For a transfer, the sponsor is the arbiter
        if (operator_ != from_) {
            revert InvalidCaller(operator_, from_);
        }
        uint256 balance = ERC6909(_COMPACT_CONTRACT).balanceOf(from_, id_);
        // Check unlocked balance
        bytes32 tokenHash = _getTokenHash(id_, from_);
        if (_claim[tokenHash] > block.timestamp ? (balance < amount_ + _amount[tokenHash]) : (balance < amount_)) {
            revert InsufficientBalance(from_, id_);
        }

        return 0x1a808f91;
    }

    /// @dev we trust the compact contract to check the nonce is not already consumed
    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4 magicValue) {
        bytes32 tokenHash = _sponsor[hash];
        if (tokenHash == bytes32(0) || _claim[tokenHash] <= block.timestamp) {
            revert InvalidLock(hash, _claim[tokenHash]);
        }

        return IERC1271.isValidSignature.selector;
    }

    function checkTokensLocked(uint256 id_, address sponsor_) internal view returns (uint256 amount_, uint256 expires_) {
        bytes32 tokenHash = _getTokenHash(id_, sponsor_);
        uint256 expires = _claim[tokenHash];
        if (expires <= block.timestamp) {
            return (0, 0);
        }

        return (_amount[tokenHash], expires);
    }

    function checkCompactLocked(Compact calldata compact_) external view returns (bool locked_, uint256 expires_) {
        // TODO: Check the force unlock time in the compact contract and adapt expires_ if needed
        if (compact_.arbiter != _ARBITER) {
            revert InvalidArbiter(compact_.arbiter);
        }
        bytes32 tokenHash = _getTokenHash(compact_.id, compact_.sponsor);
        bytes32 digest = keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                ITheCompact(_COMPACT_CONTRACT).DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)"),
                        compact_.arbiter,
                        compact_.sponsor,
                        compact_.nonce,
                        compact_.expires,
                        compact_.id,
                        compact_.amount
                    )
                )
            )
        );
        uint256 expires = _claim[tokenHash];
        return (_sponsor[digest] == tokenHash && expires > block.timestamp && !ITheCompact(_COMPACT_CONTRACT).hasConsumedAllocatorNonce(_nonce[tokenHash], address(this)), expires);
    }

    function _getTokenHash(uint256 id_, address sponsor_) internal pure returns (bytes32) {
        return keccak256(abi.encode(id_, sponsor_));
    }
}
