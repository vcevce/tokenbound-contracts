// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./AccountV3Modified.sol";

contract AccountV3ModifiedUpgradable is AccountV3Modified, UUPSUpgradeable {
    constructor(
        address multicallForwarder,
        address erc6551Registry,
        address guardian
    ) AccountV3Modified(multicallForwarder, erc6551Registry, guardian) {}

    function _authorizeUpgrade(address implementation) internal virtual override {
        if (!guardian.isTrustedImplementation(implementation)) revert InvalidImplementation();
        if (!_isValidExecutor(_msgSender())) revert NotAuthorized();
    }
}
