// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test, console } from "forge-std/Test.sol";
import { Tstorish } from "../../src/lib/Tstorish.sol";
import { TstorishMock } from "../../src/test/TstorishMock.sol";

contract TstorishTest is Test {
    Tstorish public tstorish;
    TstorishMock public tstorishMock;

    function setUp() public {
        tstorish = new Tstorish();
        tstorishMock = new TstorishMock();
    }

    function test_revert_tloadTestContractDeploymentFailed() public {
        uint8 nonce = 1;
        address deployer = address(0x1111111111111111111111111111111111111111);
        address tstorishExpected = address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(deployer), bytes1(nonce))))));

        address tloadTestContractExpected = address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(tstorishExpected), bytes1(0x01))))));

        vm.etch(tloadTestContractExpected, hex"5f5ffd"); // push0 push0 revert

        vm.setNonce(deployer, nonce);
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Tstorish.TloadTestContractDeploymentFailed.selector));
        new Tstorish();
    }

    function test_revert_tstoreAlreadyActivated() public {
        uint8 nonce = 1;
        address deployer = address(0x1111111111111111111111111111111111111111);

        vm.setNonce(deployer, nonce);
        vm.prank(deployer);
        Tstorish tstorishContract = new Tstorish();

        // Manipulate the tloadTestContract to revert so tstore is not supported
        address tloadTestContractExpected = address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(tstorishContract), bytes1(0x01))))));

        vm.etch(tloadTestContractExpected, hex"5f5ffd"); // push0 push0 revert

        vm.expectRevert(abi.encodeWithSelector(Tstorish.TStoreAlreadyActivated.selector));
        tstorishContract.__activateTstore();
    }

    function test_revert_TStoreNotSupported() public {
        uint8 nonce = 1;
        address deployer = address(0x1111111111111111111111111111111111111111);

        vm.setNonce(deployer, nonce);
        vm.prank(deployer);
        
        TstorishMock tstorishContract = new TstorishMock();

        // CONTINUE HERE: PROVE THAT TSTORE IS NOT SUPPORTED
        assertEq(true, false);

    }
}