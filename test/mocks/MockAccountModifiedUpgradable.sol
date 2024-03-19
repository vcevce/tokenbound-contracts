// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../../src/AccountV3Modified.sol";
import "../../src/AccountV3ModifiedUpgradable.sol";

contract MockAccountModifiedUpgradable is AccountV3ModifiedUpgradable {
    constructor(
        address multicallForwarder,
        address erc6551Registry,
        address guardian
    ) AccountV3ModifiedUpgradable(multicallForwarder, erc6551Registry, guardian) {}

    function customFunction() external pure returns (uint256) {
        return 12345;
    }
}
