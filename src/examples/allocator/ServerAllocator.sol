// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { Compact } from "src/types/EIP712Types.sol";
import { ITheCompact } from "src/interfaces/ITheCompact.sol";
import { IAllocator } from "src/interfaces/IAllocator.sol";
import { Ownable, Ownable2Step } from "lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import { ECDSA } from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import { IERC1271 } from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";

contract ServerAllocator is Ownable2Step, EIP712, IAllocator {
    using ECDSA for bytes32;

    struct RegisterAttest {
        address signer;
        bytes32 attestHash;
        uint256 expiration;
        uint256 nonce;
    }

    struct NonceConsumption {
        address signer;
        uint256[] nonces;
        bytes32[] attests;
    }

    // keccak256("Attest(address,address,address,uint256,uint256)")
    bytes4 private constant _ATTEST_SELECTOR = 0x1a808f91;

    // keccak256("RegisterAttest(address signer,bytes32 attestHash,uint256 expiration,uint256 nonce)")
    bytes32 private constant _ATTEST_TYPE_HASH = 0xaf2dfd3fe08723f490d203be627da2725f4ad38681e455221da2fc1a633bbb18;

    // keccak256("Allocator(bytes32 hash)")
    bytes32 private constant _ALLOCATOR_TYPE_HASH = 0xcdf324dc7c3490a07fbbb105911393dcbc0676ac7c6c1c32c786721de6179e70;

    // keccak256("NonceConsumption(address signer,uint256[] nonces,bytes32[] attests)")
    bytes32 private constant _NONCE_CONSUMPTION_TYPE_HASH = 0xb06793f900067653959d9bc53299ebf6b5aa5cf5f6c1a463305891a3db695f3c;

    address private immutable _COMPACT_CONTRACT;

    mapping(address => uint256) private _signers;
    address[] private _activeSigners;

    mapping(bytes32 => uint256) private _attestExpirations;
    mapping(bytes32 => uint256) private _attestCounts;
    mapping(bytes32 => bool) private _attestSignatures;

    event SignerAdded(address signer_);
    event SignerRemoved(address signer_);
    event AttestRegistered(bytes32 attest_, uint256 expiration_);
    event NoncesConsumed(uint256[] nonces_);
    event Attested(address from_, uint256 id_, uint256 amount_);

    error UnregisteredAttest(bytes32 attest_);
    error Expired(uint256 expiration_, uint256 currentTimestamp_);
    error ExpiredAttests(bytes32 attest_);
    error InvalidCaller(address caller_, address expected_);
    error InvalidSigner(address signer_);
    error InvalidSignature(bytes signature_, address signer_);
    error AlreadyUsedSig(bytes32 attest_, uint256 nonce);
    error InvalidInput();

    modifier isSigner(address signer_) {
        if (!_containsSigner(signer_)) {
            revert InvalidSigner(signer_);
        }
        _;
    }

    constructor(address owner_, address compactContract_) Ownable(owner_) EIP712("Allocator", "1") {
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

    /// @dev There is no way to uniquely identify a transfer, so the contract relies on its own accounting of registered attests.
    function registerAttest(bytes32 attest_, uint256 expiration_) external isSigner(msg.sender) {
        _registerAttest(attest_, expiration_);
    }

    /// @dev Nonce management in the RegisterAttest is only required for multiple registers of the same attest with the same expiration.
    function registerAttestViaSignature(RegisterAttest calldata attest_, bytes calldata signature_) external {
        bytes32 _attestWithNonce = keccak256(abi.encode(attest_.attestHash, attest_.expiration, attest_.nonce));
        if (_attestSignatures[_attestWithNonce]) {
            revert AlreadyUsedSig(attest_.attestHash, attest_.nonce);
        }
        address signer = _validateSignedAttest(attest_.signer, attest_.attestHash, attest_.expiration, attest_.nonce, signature_);
        if (signer != attest_.signer || !_containsSigner(signer)) {
            revert InvalidSignature(signature_, signer);
        }

        // Invalidate signature
        _attestSignatures[_attestWithNonce] = true;
        _registerAttest(attest_.attestHash, attest_.expiration);
    }

    /// @dev There is no way to uniquely identify a transfer, so the contract relies on its own accounting of registered attests.
    function attest(
        address, // operator_
        address from_,
        address, // to_
        uint256 id_,
        uint256 amount_
    ) external returns (bytes4) {
        if (msg.sender != _COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, _COMPACT_CONTRACT);
        }
        bytes32 registeredAttest = keccak256(abi.encode(from_, id_, amount_));
        uint256 count = _attestCounts[registeredAttest];

        if (count == 0) {
            revert UnregisteredAttest(registeredAttest);
        }
        for (uint256 i = count; i > 0; --i) {
            bytes32 countedAttest = keccak256(abi.encode(registeredAttest, i));
            if (_attestExpirations[countedAttest] >= block.timestamp) {
                // Found a valid registered attest
                if (i == count) {
                    // Last attest, delete
                    delete _attestExpirations[countedAttest];
                } else {
                    // Shift attest and delete from the end
                    bytes32 lastAttest = keccak256(abi.encode(registeredAttest, count));
                    _attestExpirations[countedAttest] = _attestExpirations[lastAttest];
                    delete _attestExpirations[lastAttest];
                }
                _attestCounts[registeredAttest] = --count;

                emit Attested(from_, id_, amount_);
                return _ATTEST_SELECTOR;
            }
        }

        revert ExpiredAttests(registeredAttest);
    }

    /// @dev The hashes array needs to be of the same length as the nonces array.
    /// @dev If no hash was yet registered, provide a bytes32(0) for the respective index.
    /// @dev All signers can override nonces of other signers.
    function consume(
        uint256[] calldata nonces_, // TODO: STRUCT OF ONE
        bytes32[] calldata attests_
    ) external isSigner(msg.sender) {
        if (attests_.length != nonces_.length) {
            revert InvalidInput();
        }
        _consumeNonces(nonces_, attests_);
    }

    function consumeViaSignature(NonceConsumption calldata data_, bytes calldata signature_) external {
        if (data_.attests.length != data_.nonces.length) {
            revert InvalidInput();
        }
        address signer = _validateNonceConsumption(data_, signature_);
        if (signer != data_.signer || !_containsSigner(signer)) {
            // first check is optional, can be deleted for gas efficiency
            revert InvalidSigner(signer);
        }
        _consumeNonces(data_.nonces, data_.attests);
    }

    /// @dev A registered attest will be a fallback if no valid signature was provided.
    // TODO: https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/IERC1271.sol
    function isValidSignature(bytes32 hash_, bytes calldata signature_) external view returns (bytes4 magicValue) {
        address signer = _validateSignedHash(hash_, signature_);
        if (!_containsSigner(signer)) {
            revert InvalidSignature(signature_, signer);
        }
        return IERC1271.isValidSignature.selector;
    }

    function checkIfSigner(address signer_) external view returns (bool) {
        return _containsSigner(signer_);
    }

    function getAllSigners() external view returns (address[] memory) {
        return _activeSigners;
    }

    function checkAttestExpirations(bytes32 attest_) external view returns (uint256[] memory) {
        return _checkAttestExpirations(attest_);
    }

    function checkAttestExpirations(address sponsor_, uint256 id_, uint256 amount_) external view returns (uint256[] memory) {
        return _checkAttestExpirations(keccak256(abi.encode(sponsor_, id_, amount_)));
    }

    function getCompactContract() external view returns (address) {
        return _COMPACT_CONTRACT;
    }

    function _registerAttest(bytes32 attest_, uint256 expiration_) internal {
        if (expiration_ < block.timestamp) {
            revert Expired(expiration_, block.timestamp);
        }
        uint256 count = ++_attestCounts[attest_];
        bytes32 countedAttest = keccak256(abi.encode(attest_, count));

        _attestExpirations[countedAttest] = expiration_;

        emit AttestRegistered(attest_, expiration_);
    }

    /// Todo: This will lead to always the last registered hash being consumed.
    function _consumeNonces(uint256[] calldata nonces_, bytes32[] calldata attests_) internal {
        ITheCompact(_COMPACT_CONTRACT).consume(nonces_);
        uint256 nonceLength = attests_.length;
        for (uint256 i = 0; i < nonceLength; ++i) {
            bytes32 hashToConsume = attests_[i];
            if (hashToConsume != bytes32(0)) {
                uint256 count = _attestCounts[attests_[i]];
                if (count != 0) {
                    // Consume the latest registered attest
                    delete _attestExpirations[
                        keccak256(abi.encode(attests_[i], count))
                    ];
                    _attestCounts[attests_[i]] = --count;
                }
            }
        }
        emit NoncesConsumed(nonces_);
    }

    function _validateSignedAttest(address signer_, bytes32 hash_, uint256 expiration_, uint256 nonce, bytes calldata signature_) internal view returns (address) {
        bytes32 message = _hashAttest(signer_, hash_, expiration_, nonce);
        return message.recover(signature_);
    }

    function _hashAttest(address signer_, bytes32 hash_, uint256 expiration_, uint256 nonce_) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(_ATTEST_TYPE_HASH, signer_, hash_, expiration_, nonce_)));
    }

    function _validateSignedHash(bytes32 hash_, bytes calldata signature_) internal view returns (address) {
        bytes32 message = _hashMessage(hash_);
        return message.recover(signature_);
    }

    function _hashMessage(bytes32 data_) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(_ALLOCATOR_TYPE_HASH, data_)));
    }

    function _validateNonceConsumption(NonceConsumption calldata data_, bytes calldata signature_) internal view returns (address) {
        bytes32 message = _hashNonceConsumption(data_);
        return message.recover(signature_);
    }

    function _hashNonceConsumption(NonceConsumption calldata data_) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(_NONCE_CONSUMPTION_TYPE_HASH, data_.signer, data_.nonces, data_.attests)));
    }

    function _containsSigner(address signer_) internal view returns (bool) {
        return _signers[signer_] != 0;
    }

    function _checkAttestExpirations(bytes32 attest_) internal view returns (uint256[] memory) {
        uint256 count = _attestCounts[attest_];
        if (count == 0) {
            revert UnregisteredAttest(attest_);
        }
        uint256[] memory expirations = new uint256[](count);
        for (uint256 i = count; i > 0; --i) {
            expirations[i - 1] = _attestExpirations[keccak256(abi.encode(attest_, i))];
        }
        return expirations;
    }
}
