// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;


library Errors {
    error InvalidToken();
    error InvalidBalanceChange(uint256 initialBalance, uint256 finalBalance);
    error AllocatorDenied(address allocator);
    error InvalidRegistrationDuration(uint256 duration);
    error InvalidStructTypestringOrder(string structTypestring);
    error InvalidStructName(string structTypestring);
    error NotSponsor(address caller, address sponsor);
    error AllocatorMismatch(address expectedAllocator, address allocator);
    error InvalidSignature(address signer, bytes signature);
    error NotArbiter(address caller, address arbiter);
    error InvalidValue();
    error InvalidAmount(uint256 received, uint256 expected);
    error InvalidExpiration(uint256 sigDeadline);
    error ForcedWithdrawalNotActive(uint256 id, uint256 timestamp);
    error NonceAlreadyConsumed(uint256 nonce);
    error AlreadyRegistered(address sponsor, bytes32 digest);
}
