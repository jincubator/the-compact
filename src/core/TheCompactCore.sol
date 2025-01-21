// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ERC6909 } from "solady/tokens/ERC6909.sol";
import { Scope } from "../types/Scope.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";
import { Deposit } from "./lib/Deposit.sol";
import { ITheCompactCore } from "../interfaces/ITheCompactCore.sol";

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
        _register(msg.sender, compact.sponsor, digest, compact.expires);
    }

    function registerWithWitness(ITheCompactCore.Compact calldata compact, bytes32 witness, string calldata typeString) external {
        bytes32 digest = _compactDigestWitness(compact, witness, typeString);
        _register(msg.sender, compact.sponsor, digest, compact.expires);
    }

    function transfer(address to, uint256 id, uint256 amount) public payable override returns (bool) {
        _ensureAttested(msg.sender, to, id, amount);
        return super.transfer(to, id, amount);
    }

    function transferFrom(address from, address to, uint256 id, uint256 amount) public payable override returns (bool) {
        _ensureAttested(from, to, id, amount);
        return super.transferFrom(from, to, id, amount);
    }

    function allocatedTransfer(ITheCompactCore.Transfer calldata transfer_, bytes calldata allocatorSignature) external returns (bool) {
        uint256 length = _ensureBatchAttested(msg.sender, transfer_, allocatorSignature);
        for(uint256 i = 0; i < length; ++i) {
            _transfer(address(0), msg.sender, _castToAddress(transfer_.recipients[i].recipient), transfer_.recipients[i].id, transfer_.recipients[i].amount);
        }
        return true;
    }

    function allocatedTransferFrom(ITheCompactCore.DelegatedTransfer calldata delegatedTransfer, bytes calldata allocatorSignature) external returns (bool) {
        uint256 length = _ensureBatchAttested(msg.sender, delegatedTransfer.transfer, allocatorSignature);
        for(uint256 i = 0; i < length; ++i) {
            _transfer(msg.sender, delegatedTransfer.from, _castToAddress(delegatedTransfer.transfer.recipients[i].recipient), delegatedTransfer.transfer.recipients[i].id, delegatedTransfer.transfer.recipients[i].amount);
        }
        return true;
    }

    // @notice Flexible withdrawal of tokens
    // @dev Works for server based allocators and on chain allocators
    // @dev On chain allocators can supply an empty bytes for the allocatorSignature
    function withdrawal(ITheCompactCore.Transfer calldata withdrawal_, bytes calldata allocatorSignature) external returns (bool) {
        uint256 length = _ensureBatchAttested(msg.sender, withdrawal_, allocatorSignature);
        for(uint256 i = 0; i < length; ++i) {
            _burn(msg.sender, withdrawal_.recipients[i].id, withdrawal_.recipients[i].amount); // reverts if insufficient balance
            _distribute(withdrawal_.recipients[i].id, withdrawal_.recipients[i].amount, _castToAddress(withdrawal_.recipients[i].recipient));
        }
        return true;
    }

    // @notice Flexible withdrawal of tokens delegated by a sponsor
    // @dev Works for server based allocators and on chain allocators
    // @dev Requires an approval from the sender
    function withdrawalFrom(ITheCompactCore.DelegatedTransfer calldata delegatedWithdrawal, bytes calldata sponsorSignature) external returns (bool) {
        uint256 length = _ensureBatchAttested(msg.sender, delegatedWithdrawal.transfer, sponsorSignature);
        for(uint256 i = 0; i < length; ++i) {
            _checkApproval(msg.sender, delegatedWithdrawal.from, delegatedWithdrawal.transfer.recipients[i].id, delegatedWithdrawal.transfer.recipients[i].amount);
            _burn(delegatedWithdrawal.from, delegatedWithdrawal.transfer.recipients[i].id, delegatedWithdrawal.transfer.recipients[i].amount);
            _distribute(delegatedWithdrawal.transfer.recipients[i].id, delegatedWithdrawal.transfer.recipients[i].amount, _castToAddress(delegatedWithdrawal.transfer.recipients[i].recipient));
        }
        return true;
    }

    function claim(ITheCompactCore.Claim calldata claim_, bool withdraw) external returns (bool) {
        (address allocator, ITheCompactCore.Compact memory compact) = _verifyClaim(claim_);
        _verifySignatures(_compactDigest(compact), claim_.compact.sponsor, claim_.sponsorSignature, allocator, claim_.allocatorSignature);
        uint256 length = compact.inputs.length;
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