// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "erc6551/lib/ERC6551AccountLib.sol";

import "../utils/Errors.sol";

/**
 * @title Account Lock and Unlock
 * @dev Allows the root owner of a token bound account to lock access to an account until
 * unlocked by themselves or a future owner
 */
abstract contract LockableUnlockable {
    /**
     * @notice Boolean representing the lock status of the account
     */
    bool public locked;

    event LockUpdated(bool locked);

    /**
     * @dev Locks the account until a certain timestamp
     */
    function lock() external virtual {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        address _owner = _rootTokenOwner(chainId, tokenContract, tokenId);

        if (_owner == address(0)) revert NotAuthorized();
        if (msg.sender != _owner) revert NotAuthorized();

        _beforeLock();

        locked = true;

        emit LockUpdated(true);
    }

    /**
     * @dev Unlocks the account
     */
    function unlock() external virtual {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        address _owner = _rootTokenOwner(chainId, tokenContract, tokenId);

        if (_owner == address(0)) revert NotAuthorized();
        if (msg.sender != _owner) revert NotAuthorized();

        _beforeUnlock();

        locked = false;

        emit LockUpdated(false);
    }

    /**
     * @dev Returns the current lock status of the account as a boolean
     */
    function isLocked() public view virtual returns (bool) {
        return locked;
    }

    function _rootTokenOwner(uint256 chainId, address tokenContract, uint256 tokenId)
        internal
        view
        virtual
        returns (address);

    function _beforeLock() internal virtual {}
    function _beforeUnlock() internal virtual {}
}
