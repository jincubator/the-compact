// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {COMPACT_TYPEHASH, Compact} from "src/types/EIP712Types.sol";
import {Ownable, Ownable2Step} from "lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

contract ServerAllocatorNonce is Ownable2Step, EIP712 {
    using ECDSA for bytes32;

    struct NonceConsumption {
        address signer;
        uint256[] nonces;
    }

    // keccak256("NonceConsumption(address signer,uint256[] nonces)")
    bytes32 private constant _NONCE_CONSUMPTION_TYPE_HASH =
        0x8131ea92bd36581a24ac72c3abac20376f242758e62cdeb68a74dfa4ff3bfdaa;
    address private immutable _COMPACT_CONTRACT;

    mapping(address => uint256) private _signers;
    address[] private _activeSigners;
    mapping(uint256 => bool) private _nonces;
    mapping(uint256 => bytes32) private _registeredHashes; // TODO: register this by hash => expiration instead of nonce => hash

    event SignerAdded(address signer_);
    event SignerRemoved(address signer_);
    event HashRegistered(uint256 nonce_, bytes32 hash_);
    event NonceConsumed(uint256 nonce_);

    error InvalidCaller(address caller_, address expected_);
    error InvalidSigner(address signer_);
    error InvalidHash(bytes32 hash_);
    error InvalidNonce(uint256 nonce_);

    modifier isSigner(address signer_) {
        if (!_containsSigner(signer_)) {
            revert InvalidSigner(signer_);
        }
        _;
    }

    constructor(
        address owner_,
        address compactContract_
    ) Ownable(owner_) EIP712("ServerAllocator", "1") {
        _COMPACT_CONTRACT = compactContract_;
    }

    function addSigner(address signer_) external onlyOwner {
        if (_containsSigner(signer_)) {
            return;
        }

        _activeSigners.push(signer_);
        _signers[signer_] = _activeSigners.length;

        emit SignerAdded(signer_);
    }

    function removeSigner(address signer_) external onlyOwner {
        if (!_containsSigner(signer_)) {
            return;
        }

        uint256 index = _signers[signer_] - 1;
        _activeSigners[index] = _activeSigners[_activeSigners.length - 1];
        _activeSigners.pop();

        _signers[signer_] = 0;

        emit SignerRemoved(signer_);
    }

    function registerHash(
        bytes32 hash_,
        uint256 nonce_
    ) external isSigner(msg.sender) {
        if (_nonceUsed(nonce_) || _registeredHashes[nonce_] != bytes32(0)) {
            revert InvalidNonce(nonce_);
        }
        bytes32 noncedHash = keccak256(abi.encode(hash_, nonce_));
        _registeredHashes[nonce_] = noncedHash;

        emit HashRegistered(nonce_, hash_);
    }

    function attest(
        address from_,
        uint256 id_,
        uint256 amount_,
        uint256 nonce_
    ) external {
        if (msg.sender != _COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, _COMPACT_CONTRACT);
        }
        if (_nonceUsed(nonce_)) {
            revert InvalidNonce(nonce_);
        }
        bytes32 cleanHash = keccak256(abi.encode(from_, id_, amount_));
        bytes32 noncedHash = keccak256(abi.encode(cleanHash, nonce_));

        if (_registeredHashes[nonce_] != noncedHash) {
            revert InvalidHash(noncedHash);
        }
        _consumeNonce(nonce_);
    }

    /// @dev Treating the nonces individually instead of sequentially
    /// TODO: All signers can override nonces of other signers. This allows to consume nonces while attesting.
    function consume(uint256[] calldata nonces_) external isSigner(msg.sender) {
        _consumeNonces(nonces_);
    }

    function consumeViaSignature(
        NonceConsumption calldata data_,
        bytes calldata signature_
    ) external {
        address signer = _validateNonceConsumption(data_, signature_);
        if (signer != data_.signer) {
            // check is optional, would fail if signer is not a registered signer anyway
            revert InvalidSigner(signer);
        }
        if (!_containsSigner(signer)) {
            revert InvalidSigner(signer);
        }
        _consumeNonces(data_.nonces);
    }

    function isValidSignature(
        Compact calldata data_,
        bytes calldata signature_,
        bool checkHash_
    ) external view returns (bool) {
        if (data_.expires < block.timestamp) {
            return false;
        }
        if (_nonceUsed(data_.nonce)) {
            return false;
        }
        if (checkHash_ && _registeredHashes[data_.nonce] == bytes32(0)) {
            return false;
        }

        address signer = _validateData(data_, signature_);
        return _containsSigner(signer);
    }

    function checkIfSigner(address signer_) external view returns (bool) {
        return _containsSigner(signer_);
    }

    function getAllSigners() external view returns (address[] memory) {
        return _activeSigners;
    }

    function checkNonceConsumed(uint256 nonce_) external view returns (bool) {
        return _nonceUsed(nonce_);
    }

    function checkNonceFree(uint256 nonce_) external view returns (bool) {
        return !_nonceUsed(nonce_) && _registeredHashes[nonce_] == bytes32(0);
    }

    function getCompactContract() external view returns (address) {
        return _COMPACT_CONTRACT;
    }

    function _consumeNonces(uint256[] calldata nonces_) internal {
        uint256 nonceLength = nonces_.length;
        for (uint256 i = 0; i < nonceLength; ++i) {
            _consumeNonce(nonces_[i]);
        }
    }

    function _consumeNonce(uint256 nonce_) internal {
        delete _registeredHashes[nonce_];
        _nonces[nonce_] = true;

        emit NonceConsumed(nonce_);
    }

    function _validateData(
        Compact calldata data_,
        bytes calldata signature_
    ) internal view returns (address) {
        bytes32 message = _hashCompact(data_);
        return message.recover(signature_);
    }

    function _hashCompact(
        Compact calldata data_
    ) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        COMPACT_TYPEHASH,
                        data_.arbiter,
                        data_.sponsor,
                        data_.nonce,
                        data_.expires,
                        data_.id,
                        data_.amount
                    )
                )
            );
    }

    function _validateNonceConsumption(
        NonceConsumption calldata data_,
        bytes calldata signature_
    ) internal view returns (address) {
        bytes32 message = _hashNonceConsumption(data_);
        return message.recover(signature_);
    }

    function _hashNonceConsumption(
        NonceConsumption calldata data_
    ) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        _NONCE_CONSUMPTION_TYPE_HASH,
                        data_.signer,
                        data_.nonces
                    )
                )
            );
    }

    function _nonceUsed(uint256 nonce_) internal view returns (bool) {
        return _nonces[nonce_];
    }

    function _containsSigner(address signer_) internal view returns (bool) {
        return _signers[signer_] != 0;
    }
}
