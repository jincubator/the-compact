// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    TransferBenchmarkLib,
    _NATIVE_TOKEN_BENCHMARK_SCOPE,
    _ERC20_TOKEN_BENCHMARK_SCOPE
} from "./TransferBenchmarkLib.sol";

import { TransferBenchmarker } from "./TransferBenchmarker.sol";

/**
 * @title TransferBenchmarkLogic
 * @notice Inherited contract implementing logic for benchmarking the approximate
 * cost of both native token withdrawals as well as generic ERC20 token withdrawals.
 * Deploys a benchmark ERC20 token during contract creation for use in benchmarking.
 */
contract TransferBenchmarkLogic {
    using TransferBenchmarkLib for uint256;

    // Declare an immutable argument for the account of the benchmarker contract.
    address private immutable _BENCHMARKER;

    constructor() {
        // Deploy contract for benchmarking native and generic ERC20 token withdrawals. Note
        // that benchmark cannot be evaluated as part of contract creation as it requires
        // that the ERC20 account is not already warm as part of deriving the benchmark.
        _BENCHMARKER = address(new TransferBenchmarker());
    }

    /**
     * @notice Internal function to benchmark the gas costs of token transfers.
     * Measures both native token and ERC20 token transfer costs and stores them.
     */
    function _benchmark() internal {
        address benchmarker = _BENCHMARKER;

        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let success := call(gas(), benchmarker, callvalue(), 0, calldatasize(), 0, 0x40)
            if iszero(success) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }

            sstore(_NATIVE_TOKEN_BENCHMARK_SCOPE, mload(0))
            sstore(_ERC20_TOKEN_BENCHMARK_SCOPE, mload(0x20))
        }
    }

    /**
     * @notice Internal view function for retrieving the benchmarked gas costs for
     * both native token and ERC20 token withdrawals.
     * @return nativeTokenStipend The benchmarked gas cost for native token withdrawals.
     * @return erc20TokenStipend  The benchmarked gas cost for ERC20 token withdrawals.
     */
    function _getRequiredWithdrawalFallbackStipends()
        internal
        view
        returns (uint256 nativeTokenStipend, uint256 erc20TokenStipend)
    {
        assembly ("memory-safe") {
            nativeTokenStipend := sload(_NATIVE_TOKEN_BENCHMARK_SCOPE)
            erc20TokenStipend := sload(_ERC20_TOKEN_BENCHMARK_SCOPE)
        }
    }
}
