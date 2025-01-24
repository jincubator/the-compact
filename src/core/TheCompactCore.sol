// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { IdLib } from "../lib/IdLib.sol";
import { Scope } from "../types/Scope.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Deposit } from "./lib/Deposit.sol";
import { ITheCompactCore } from "../interfaces/ITheCompactCore.sol";
import { Errors } from "./lib/Errors.sol";

contract TheCompactCore is ERC6909, Deposit {

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

    function depositAndRegister(ITheCompactCore.Compact calldata compact, bytes32 witness, string calldata typeString) external payable returns (ITheCompactCore.Compact memory registeredCompact) {
        registeredCompact = compact;
        uint256 length = compact.inputs.length;
        uint256 nativeAmount = msg.value;
        bool delegated = msg.sender != compact.sponsor;
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
            if(delegated) {
                registeredCompact.inputs[i].recipient = _markDelegation(registeredCompact.inputs[i].recipient, msg.sender);
            }
        }
        bytes32 digest = witness != bytes32(0) ? _compactDigestWitness(compact, witness, typeString) : _compactDigest(compact);
        _register(compact.sponsor, digest, compact.expires);
        return registeredCompact;
    }

    function setOperator(address operator, bool approved) public payable override returns (bool) {
        if(msg.value > 0) {
            revert Errors.InvalidValue();
        }
        return super.setOperator(operator, approved);
    }

    function approve(address spender, uint256 id, uint256 amount) public payable override returns (bool) {
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

    function transfer(address to, uint256 id, uint256 amount) public payable override returns (bool) {
        if(msg.value > 0) {
            revert Errors.InvalidValue();
        }
        _ensureAttested(msg.sender, to, id, amount);
        return super.transfer(to, id, amount);
    }

    function transferFrom(address from, address to, uint256 id, uint256 amount) public payable override returns (bool) {
        if(msg.value > 0) {
            revert Errors.InvalidValue();
        }
        _ensureAttested(from, to, id, amount);
        return super.transferFrom(from, to, id, amount);
    }

    function allocatedTransfer(ITheCompactCore.Transfer calldata transfer_, bytes calldata allocatorSignature) external returns (bool) {
        address allocator = _checkNonce(transfer_.recipients[0].id, transfer_.nonce);
        uint256 length = _ensureBatchAttested(msg.sender, transfer_, allocatorSignature);
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
        uint256 length = _ensureBatchAttested(msg.sender, delegatedTransfer.transfer, allocatorSignature);
        // The allocator has successfully attested to the withdrawal. If the nonce is not 0, it must be consumed
        if(delegatedTransfer.transfer.nonce != 0) {
            // If the nonce is 0, it must be an on chain allocator that does not require a nonce to attest.
            _consumeNonce(allocator, delegatedTransfer.transfer.nonce);
        }
        for(uint256 i = 0; i < length; ++i) {
            _transfer(msg.sender, delegatedTransfer.from, _castToAddress(delegatedTransfer.transfer.recipients[i].recipient), delegatedTransfer.transfer.recipients[i].id, delegatedTransfer.transfer.recipients[i].amount);
            // TODO: consume nonce if not 0 (so not an on chain allocator)
        }
        return true;
    }

    function withdrawal(ITheCompactCore.Transfer calldata withdrawal_, bytes calldata allocatorSignature) external returns (bool) {
        address allocator = _checkNonce(withdrawal_.recipients[0].id, withdrawal_.nonce);
        uint256 length = _ensureBatchAttested(msg.sender, withdrawal_, allocatorSignature);
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
        uint256 length = _ensureBatchAttested(msg.sender, delegatedWithdrawal.transfer, allocatorSignature);
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
        // The allocator has successfully attested to the withdrawal. If the nonce is not 0, it must be consumed
        if(claim_.compact.nonce != 0) {
            // If the nonce is 0, it must be an on chain allocator that does not require a nonce to attest.
            _consumeNonce(allocator, claim_.compact.nonce);
        }        
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
        // The allocator has successfully attested to the withdrawal. If the nonce is not 0, it must be consumed
        if(claim_.compact.nonce != 0) {
            // If the nonce is 0, it must be an on chain allocator that does not require a nonce to attest.
            _consumeNonce(allocator, claim_.compact.nonce);
        }
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

    function getPermitNonce(address owner) external view returns (uint256) {
        return _getPermit2Nonce(owner);
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