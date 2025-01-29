// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

interface ITheCompactService {
    function getClaimFee(uint256 id, uint256 amount) external view returns (uint256 fee, uint256 remainingAmount);
}