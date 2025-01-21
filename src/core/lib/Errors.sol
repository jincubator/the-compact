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
}
