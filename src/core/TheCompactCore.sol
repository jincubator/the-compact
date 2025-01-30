// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { IdLib } from "../lib/IdLib.sol";
import { Scope } from "../types/Scope.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { ITheCompactMultiChain } from "../interfaces/ITheCompactMultiChain.sol";
import { ITheCompactCore } from "../interfaces/ITheCompactCore.sol";
import { IAllocator } from "../interfaces/IAllocator.sol";
import { ITheCompactService } from "../interfaces/ITheCompactService.sol";
import { Errors } from "./lib/Errors.sol";
import { TheCompactLogic } from "./lib/TheCompactLogic.sol";

contract TheCompactCore is ERC6909, TheCompactLogic, ITheCompactCore, ITheCompactMultiChain {

    error InvalidToken();

    function deposit(address allocator, Scope scope, ResetPeriod resetPeriod, address recipient) external payable returns (uint256 id) {
        return _deposit(address(0), msg.value, allocator, scope, resetPeriod, recipient);
    }

    function deposit(address token, uint256 amount, address allocator, ResetPeriod resetPeriod, Scope scope, address recipient) external returns (uint256) {
        // Collects the tokens from the sender, reverts if the token is zero address. Returns the actual received amount
        amount = _collect(token, amount, msg.sender);
        return _deposit(token, amount, allocator, scope, resetPeriod, recipient);
    }

    function register(ITheCompactCore.Compact calldata compact) external {
        bytes32 digest = _compactDigest(compact);
        if(msg.sender != compact.sponsor) {
            revert Errors.NotSponsor(msg.sender, compact.sponsor);
        }
        _register(compact.sponsor, digest, compact.expires);
    }

    function registerWithWitness(ITheCompactCore.Compact calldata compact, bytes32 witness, string calldata typeString) external {
        bytes32 digest = _compactDigestWitness(compact, witness, typeString);
        if(msg.sender != compact.sponsor) {
            revert Errors.NotSponsor(msg.sender, compact.sponsor);
        }
        _register(compact.sponsor, digest, compact.expires);
    }

    function multiChainRegister(ITheCompactMultiChain.EnhancedCompact[] calldata compacts, bytes32 witness, string calldata typeString) external {
        (ITheCompactCore.Compact memory compact, ) = _verifyMultiChain(compacts);
        bytes32 digest = witness != bytes32(0) ? _compactDigestWithWitnessMultiChain(compacts, witness, typeString) : _compactDigestMultiChain(compacts);
        if(msg.sender != compact.sponsor) {
            revert Errors.NotSponsor(msg.sender, compact.sponsor);
        }
        _register(compact.sponsor, digest, compact.expires);
    }

    function depositAndRegister(ITheCompactCore.Compact calldata compact, bytes32 witness, string calldata typeString) external payable {
        _depositAllInputs(compact);
        bytes32 digest = witness != bytes32(0) ? _compactDigestWitness(compact, witness, typeString) : _compactDigest(compact);
        _register(compact.sponsor, digest, compact.expires);
    }

    function multiChainDepositAndRegister(ITheCompactMultiChain.EnhancedCompact[] calldata compacts, bytes32 witness, string calldata typeString) external payable {
        (ITheCompactCore.Compact memory compact, ) = _verifyMultiChain(compacts);
        _depositAllInputs(compact);
        bytes32 digest = witness != bytes32(0) ? _compactDigestWithWitnessMultiChain(compacts, witness, typeString) : _compactDigestMultiChain(compacts);
        _register(compact.sponsor, digest, compact.expires);
    }

    function setOperator(address operator, bool approved) public payable override (ERC6909, ITheCompactCore) returns (bool) {
        if(msg.value > 0) {
            revert Errors.InvalidValue();
        }
        return super.setOperator(operator, approved);
    }

    function approve(address spender, uint256 id, uint256 amount) public payable override (ERC6909, ITheCompactCore) returns (bool) {
        if(msg.value > 0) {
            revert Errors.InvalidValue();
        }
        return super.approve(spender, id, amount);
    }

    function permit(
        address owner,
        address spender,
        uint256 id,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    ) external returns (bool) {
        _checkPermit(owner, spender, value, id, deadline, signature);
        _approve(owner, spender, id, value);
        return true;
    }

    // function transientPermit(
    //     address owner,
    //     address spender,
    //     uint256 id,
    //     uint256 amount,
    //     uint256 deadline,
    //     bytes calldata signature
    // ) public returns (bool) {
    //     _checkPermit(owner, spender, amount, id, deadline, signature);
    //     // _approveTStore(owner, spender, id, amount);
    //     return true;
    // }

    function transfer(address to, uint256 id, uint256 amount) public payable override (ERC6909, ITheCompactCore) returns (bool) {
        if(msg.value > 0) {
            revert Errors.InvalidValue();
        }
        _ensureAttested(msg.sender, to, id, amount);
        return super.transfer(to, id, amount);
    }

    function transferFrom(address from, address to, uint256 id, uint256 amount) public payable override (ERC6909, ITheCompactCore) returns (bool) {
        if(msg.value > 0) {
            revert Errors.InvalidValue();
        }
        _ensureAttested(from, to, id, amount);
        return super.transferFrom(from, to, id, amount);
    }

    function allocatedTransfer(ITheCompactCore.TokenTransfer calldata transfer_, bytes calldata allocatorSignature) external returns (bool) {
        address allocator = _checkNonce(transfer_.recipients[0].id, transfer_.nonce);
        uint256 length = _ensureBatchAttested(msg.sender, msg.sender, transfer_, allocatorSignature);
        // The allocator has successfully attested to the withdrawal. If the nonce is not 0, it must be consumed
        if(transfer_.nonce != 0) {
            // If the nonce is 0, it must be an on chain allocator that does not require a nonce to attest.
            _consumeNonce(allocator, transfer_.nonce);
        }
        for(uint256 i = 0; i < length; ++i) {
            _transfer(address(0), msg.sender, _castToAddress(transfer_.recipients[i].recipient), transfer_.recipients[i].id, transfer_.recipients[i].amount);
            // TODO: consume nonce if not 0 (so not an on chain allocator)
        }
        return true;
    }

    function allocatedTransferFrom(ITheCompactCore.DelegatedTransfer calldata delegatedTransfer, bytes calldata allocatorSignature) external returns (bool) {
        address allocator = _checkNonce(delegatedTransfer.transfer.recipients[0].id, delegatedTransfer.transfer.nonce);
        uint256 length = _ensureBatchAttested(msg.sender, delegatedTransfer.from, delegatedTransfer.transfer, allocatorSignature);
        // The allocator has successfully attested to the withdrawal. If the nonce is not 0, it must be consumed
        if(delegatedTransfer.transfer.nonce != 0) {
            // If the nonce is 0, it must be an on chain allocator that does not require a nonce to attest.
            _consumeNonce(allocator, delegatedTransfer.transfer.nonce);
        }
        for(uint256 i = 0; i < length; ++i) {
            _transfer(msg.sender, delegatedTransfer.from, _castToAddress(delegatedTransfer.transfer.recipients[i].recipient), delegatedTransfer.transfer.recipients[i].id, delegatedTransfer.transfer.recipients[i].amount);
        }
        return true;
    }

    function withdrawal(ITheCompactCore.Transfer calldata withdrawal_, bytes calldata allocatorSignature) external returns (bool) {
        address allocator = _checkNonce(withdrawal_.recipients[0].id, withdrawal_.nonce);
        uint256 length = _ensureBatchAttested(msg.sender, msg.sender, withdrawal_, allocatorSignature);
        // The allocator has successfully attested to the withdrawal. If the nonce is not 0, it must be consumed
        if(withdrawal_.nonce != 0) {
            // If the nonce is 0, it must be an on chain allocator that does not require a nonce to attest.
            _consumeNonce(allocator, withdrawal_.nonce);
        }
        for(uint256 i = 0; i < length; ++i) {
            _burn(msg.sender, withdrawal_.recipients[i].id, withdrawal_.recipients[i].amount); // reverts if insufficient balance
            _distribute(withdrawal_.recipients[i].id, withdrawal_.recipients[i].amount, _castToAddress(withdrawal_.recipients[i].recipient));
            // TODO: consume nonce if not 0 (so not an on chain allocator)
        }
        return true;
    }

    function withdrawalFrom(ITheCompactCore.DelegatedTransfer calldata delegatedWithdrawal, bytes calldata allocatorSignature) external returns (bool) {
        address allocator = _checkNonce(delegatedWithdrawal.transfer.recipients[0].id, delegatedWithdrawal.transfer.nonce);
        uint256 length = _ensureBatchAttested(msg.sender, delegatedWithdrawal.from, delegatedWithdrawal.transfer, allocatorSignature);
        // The allocator has successfully attested to the withdrawal. If the nonce is not 0, it must be consumed
        if(delegatedWithdrawal.transfer.nonce != 0) {
            // If the nonce is 0, it must be an on chain allocator that does not require a nonce to attest.
            _consumeNonce(allocator, delegatedWithdrawal.transfer.nonce);
        }
        for(uint256 i = 0; i < length; ++i) {
            _checkApproval(msg.sender, delegatedWithdrawal.from, delegatedWithdrawal.transfer.recipients[i].id, delegatedWithdrawal.transfer.recipients[i].amount);
            _burn(delegatedWithdrawal.from, delegatedWithdrawal.transfer.recipients[i].id, delegatedWithdrawal.transfer.recipients[i].amount);
            _distribute(delegatedWithdrawal.transfer.recipients[i].id, delegatedWithdrawal.transfer.recipients[i].amount, _castToAddress(delegatedWithdrawal.transfer.recipients[i].recipient));
            // TODO: consume nonce if not 0 (so not an on chain allocator)
        }
        return true;
    }

    function claim(ITheCompactCore.Claim calldata claim_, bool withdraw) external returns (bool) {
        (address allocator, ITheCompactCore.Compact memory compact) = _verifyClaim(claim_);
        _checkNonce(allocator, claim_.compact.nonce);
        bytes32 digest = claim_.witness == bytes32(0) ? _compactDigest(compact) : _compactDigestWitness(compact, claim_.witness, claim_.typeString);
        _verifySignatures(digest, claim_.compact.sponsor, claim_.sponsorSignature, digest, allocator, claim_.allocatorSignature);
        // The allocator has successfully attested to the withdrawal. Consuming the nonce  
        _consumeNonce(allocator, claim_.compact.nonce);
        uint256 length = claim_.compact.inputs.length;
        for(uint256 i = 0; i < length; ++i) {
            if(withdraw) {
                _burn(claim_.compact.sponsor, claim_.compact.inputs[i].id, claim_.compact.inputs[i].amount);
                _distribute(claim_.compact.inputs[i].id, claim_.compact.inputs[i].amount, _castToAddress(claim_.compact.inputs[i].recipient));
            } else {
                _rebalance(claim_.compact.sponsor, _castToAddress(claim_.compact.inputs[i].recipient), claim_.compact.inputs[i].id, claim_.compact.inputs[i].amount, false);
                // TODO: add event
            }
        }
        return true;
    }

    function claimWithQualification(ITheCompactCore.Claim calldata claim_, bytes32 qualificationHash, string calldata qualificationTypeString, bool withdraw) external returns (bool) {
        (address allocator, ITheCompactCore.Compact memory compact) = _verifyClaim(claim_);
        _checkNonce(allocator, claim_.compact.nonce);
        bytes32 digest = claim_.witness == bytes32(0) ? _compactDigest(compact) : _compactDigestWitness(compact, claim_.witness, claim_.typeString);
        bytes32 allocatorDigest = _compactDigestQualification(digest, qualificationHash, qualificationTypeString);
        _verifySignatures(digest, claim_.compact.sponsor, claim_.sponsorSignature, allocatorDigest, allocator, claim_.allocatorSignature);
        // The allocator has successfully attested to the withdrawal. Consuming the nonce  
        _consumeNonce(allocator, claim_.compact.nonce);
        uint256 length = claim_.compact.inputs.length;
        for(uint256 i = 0; i < length; ++i) {
            if(withdraw) {
                _burn(claim_.compact.sponsor, claim_.compact.inputs[i].id, claim_.compact.inputs[i].amount);
                _distribute(claim_.compact.inputs[i].id, claim_.compact.inputs[i].amount, _castToAddress(claim_.compact.inputs[i].recipient));
            } else {
                _rebalance(claim_.compact.sponsor, _castToAddress(claim_.compact.inputs[i].recipient), claim_.compact.inputs[i].id, claim_.compact.inputs[i].amount, false);
                // TODO: add event
            }
        }
        return true;
    }

    function multiChainClaim(ITheCompactMultiChain.EnhancedClaim calldata claim_, bytes32 qualificationHash, string calldata qualificationTypeString, bool withdraw) external returns (bool) {
        (,uint256 relevantIndex) = _verifyMultiChain(claim_.compacts);
        (address allocator, ITheCompactCore.Compact memory compact) = _verifyEnhancedClaim(claim_, relevantIndex);
        // Check only the nonce of the relevant compact
        _checkNonce(allocator, compact.nonce);

        // Replace the compact of this chain with the cleaned up version without the unknown recipients and using it to create the digest
        ITheCompactMultiChain.EnhancedCompact[] memory cleanedCompacts_ = claim_.compacts;
        cleanedCompacts_[relevantIndex].compact = compact;

        bytes32 digest = claim_.witness == bytes32(0) ? _compactDigestMultiChain(cleanedCompacts_) : _compactDigestWithWitnessMultiChain(cleanedCompacts_, claim_.witness, claim_.typeString);
        bytes32 allocatorDigest = digest;
        if(qualificationHash != bytes32(0)) {
            allocatorDigest = _compactDigestQualification(digest, qualificationHash, qualificationTypeString);
        }
        _verifySignatures(digest, compact.sponsor, claim_.sponsorSignature, allocatorDigest, allocator, claim_.allocatorSignature);
        // The allocator has successfully attested to the withdrawal. Consuming the nonce  
        _consumeNonce(allocator, compact.nonce);
        uint256 length = claim_.compacts[relevantIndex].compact.inputs.length;
        for(uint256 i = 0; i < length; ++i) {
            ITheCompactCore.Allocation memory input = claim_.compacts[relevantIndex].compact.inputs[i];
            if(withdraw) {
                _burn(compact.sponsor, input.id, input.amount);
                _distribute(input.id, input.amount, _castToAddress(input.recipient));
            } else {
                _rebalance(compact.sponsor, _castToAddress(input.recipient), input.id, input.amount, false);
                // TODO: add event
            }
        }
        return true;
    }

    function enableForcedWithdrawal(uint256[] calldata ids) external returns (uint256[] memory) {
        uint256 length = ids.length;
        uint256[] memory withdrawableAt = new uint256[](length);
        for(uint256 i = 0; i < length; ++i) {
            withdrawableAt[i] = _changeForceWithdrawalStart(ids[i], true);
        }
        return withdrawableAt;
    }

    function disableForcedWithdrawal(uint256[] calldata ids) external returns (uint256[] memory withdrawableAt) {
        uint256 length = ids.length;
        uint256[] memory timestamps = new uint256[](length);
        for(uint256 i = 0; i < length; ++i) {
            timestamps[i] = _changeForceWithdrawalStart(ids[i], false);
        }
        return timestamps;
    }

    function forcedWithdrawal(uint256[] calldata ids, address recipient) external returns (bool) {
        uint256 length = ids.length;
        for(uint256 i = 0; i < length; ++i) {
            _checkForceWithdrawalStart(ids[i]);
            uint256 balance = balanceOf(msg.sender, ids[i]);
            _burn(msg.sender, ids[i], balance); // reverts if insufficient balance
            _distribute(ids[i], balance, recipient);
        }
        return true;
    }

    function consume(uint256[] calldata nonces) external returns (bool) {
        uint256 length = nonces.length;
        for(uint256 i = 0; i < length; ++i) {
            _consumeNonce(msg.sender, nonces[i]);
        }
        return true;
    }

    function __registerAllocator(address allocator, bytes calldata proof) external returns (uint96 allocatorId) {
        allocator = _sanitizeAddress(allocator);
        if (!IdLib.canBeRegistered(allocator, proof)) {
            revert Errors.InvalidRegistrationProof(allocator);
        }
        allocatorId = IdLib.register(allocator);
    }

    function getClaimFee(address[] calldata providers, uint256 id, uint256 amount) external view returns (uint256[] memory, uint256 remainingAmount) {
        uint256 length = providers.length;
        uint256[] memory fees = new uint256[](length);
        for(uint256 i = 0; i < length; ++i) {
            (fees[i],) = ITheCompactService(providers[i]).getClaimFee(id, amount);
            if(fees[i] > remainingAmount) {
                revert Errors.InvalidAmount(fees[i], remainingAmount);
            }
            remainingAmount -= fees[i];
        }
        return (fees, remainingAmount);
    }

    function getForcedWithdrawalStatus(address sponsor, uint256 id) external view returns (uint256 availableAt) {
        return _getForceWithdrawalStart(sponsor, id);
    }

    function hasConsumedAllocatorNonce(uint256 nonce, address allocator) external view returns (bool consumed) {
        return _nonceConsumed(allocator, nonce);
    }

    function getPermitNonce(address owner) external view returns (uint256) {
        return _getPermit2Nonce(owner);
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32 domainSeparator) {
        return _DOMAIN_SEPARATOR;
    }

    /// @dev Returns the name for the contract.
    function name() external pure returns (string memory) {
        return _NAME;
    }

    function version() external pure returns (string memory) {
        return _VERSION;
    }

    /// @dev Returns the symbol for token `id`.
    function name(uint256) public view virtual override returns (string memory) {
        return "";
    }

    /// @dev Returns the symbol for token `id`.
    function symbol(uint256) public view virtual override returns (string memory) {
        return "";
    }

    /// @dev Returns the Uniform Resource Identifier (URI) for token `id`.
    function tokenURI(uint256) public view virtual override returns (string memory) {
        return "";
    }
}