// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Tstorish } from "../lib/Tstorish.sol";

contract TstorishMock is Tstorish {

    function _testTload(address tloadTestContract) internal view override returns (bool ok) {
        return tloadTestContract.code.length == 0;
    }
}
