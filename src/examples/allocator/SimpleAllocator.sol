// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { ERC6909 } from "lib/solady/src/tokens/ERC6909.sol";
import { IERC1271 } from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import { IAllocator } from "src/interfaces/IAllocator.sol";
import { ITheCompact } from "src/interfaces/ITheCompact.sol";
import { ISimpleAllocator } from "src/interfaces/ISimpleAllocator.sol";
import { Compact } from "src/types/EIP712Types.sol";
import { ResetPeriod } from "src/lib/IdLib.sol";

contract SimpleAllocator is ISimpleAllocator {

    address private immutable _COMPACT_CONTRACT;
    address private immutable _ARBITER;
    uint256 private immutable _MIN_WITHDRAWAL_DELAY;
    uint256 private immutable _MAX_WITHDRAWAL_DELAY;

    /// @dev mapping of tokenHash to the expiration of the lock
    mapping(bytes32 tokenHash => uint256 expiration) private _claim;
    /// @dev mapping of tokenHash to the amount of the lock
    mapping(bytes32 tokenHash => uint256 amount) private _amount;
    /// @dev mapping of tokenHash to the nonce of the lock
    mapping(bytes32 tokenHash => uint256 nonce) private _nonce;
    /// @dev mapping of the lock digest to the tokenHash of the lock
    mapping(bytes32 digest => bytes32 tokenHash) private _sponsor;

    constructor(address compactContract_, address arbiter_, uint256 minWithdrawalDelay_, uint256 maxWithdrawalDelay_) {
        _COMPACT_CONTRACT = compactContract_;
        _ARBITER = arbiter_;
        _MIN_WITHDRAWAL_DELAY = minWithdrawalDelay_;
        _MAX_WITHDRAWAL_DELAY = maxWithdrawalDelay_;
    }

    /// @inheritdoc ISimpleAllocator
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
        // Check expiration is not longer then the tokens forced withdrawal time
        (,, ResetPeriod resetPeriod, ) = ITheCompact(_COMPACT_CONTRACT).getLockDetails(compact_.id);
        if(compact_.expires > block.timestamp + _resetPeriodToSeconds(resetPeriod) ){
            revert ForceWithdrawalAvailable(compact_.expires, block.timestamp + _resetPeriodToSeconds(resetPeriod));
        }
        // Check expiration is not past an active force withdrawal
        (, uint256 forcedWithdrawalExpiration) = ITheCompact(_COMPACT_CONTRACT).getForcedWithdrawalStatus(compact_.sponsor, compact_.id);
        if(forcedWithdrawalExpiration != 0 &&  forcedWithdrawalExpiration < compact_.expires) {
            revert ForceWithdrawalAvailable(compact_.expires, forcedWithdrawalExpiration);
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

    /// @inheritdoc IAllocator
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

        uint256 fullAmount = amount_;
        if(_claim[tokenHash] > block.timestamp) {
            // Lock is still active, add the locked amount if the nonce has not yet been consumed
            fullAmount += ITheCompact(_COMPACT_CONTRACT).hasConsumedAllocatorNonce(_nonce[tokenHash], address(this)) ? 0 : _amount[tokenHash];
        }
        if( balance < fullAmount) {
            revert InsufficientBalance(from_, id_);
        }

        return 0x1a808f91;
    }

    /// @inheritdoc IERC1271
    /// @dev we trust the compact contract to check the nonce is not already consumed
    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4 magicValue) {
        // The hash is the digest of the compact
        bytes32 tokenHash = _sponsor[hash];
        if (tokenHash == bytes32(0) || _claim[tokenHash] <= block.timestamp) {
            revert InvalidLock(hash, _claim[tokenHash]);
        }

        return IERC1271.isValidSignature.selector;
    }

    /// @inheritdoc ISimpleAllocator
    function checkTokensLocked(uint256 id_, address sponsor_) external view returns (uint256 amount_, uint256 expires_) {
        bytes32 tokenHash = _getTokenHash(id_, sponsor_);
        uint256 expires = _claim[tokenHash];
        if (expires <= block.timestamp) {
            return (0, 0);
        }

        return (_amount[tokenHash], expires);
    }

    /// @inheritdoc ISimpleAllocator
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

    /// @dev copied from IdLib.sol
    function _resetPeriodToSeconds(ResetPeriod resetPeriod_) internal pure returns (uint256 duration) {
        assembly ("memory-safe") {
            // Bitpacked durations in 24-bit segments:
            // 278d00  094890  015180  000f3c  000258  00003c  00000f  000001
            // 30 days 7 days  1 day   1 hour  10 min  1 min   15 sec  1 sec
            let bitpacked := 0x278d00094890015180000f3c00025800003c00000f000001

            // Shift right by period * 24 bits & mask the least significant 24 bits.
            duration := and(shr(mul(resetPeriod_, 24), bitpacked), 0xffffff)
        }
        return duration;
    }
}
