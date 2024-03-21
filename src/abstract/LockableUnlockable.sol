// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "erc6551/lib/ERC6551AccountLib.sol";

import "../utils/Errors.sol";

/**
 * @title Account Lock and Unlock
 * @dev Allows the root owner of a token bound account to lock access to an account
 *
 * A User can either lock their account until a certain time, or soft lock their account.
 * The User may soft lock to lock in assets for a buy-it-now sale, or to prevent use of the account.
 * The User may hard lock to lock in assets for all marketplace sales (bids, etc).
 *
 * @dev A soft lock is a lock that can be removed by the root owner at any time
 * @dev A hard/time lock is a lock that can only be removed at its expiration, or on token transfer
 */
abstract contract LockableUnlockable {
    /**
     * @notice Boolean representing the soft lock status of the account
     * A soft lock is a lock that can be removed by the root owner at any time
     */
    bool public softLocked;

    /**
     * @notice The timestamp at which this account will be unlocked
     * A hard/time lock is a lock that can only be removed at expiration, or on token transfer
     */
    uint256 public lockedUntil;

    event LockUpdated(bool softLocked, uint256 lockedUntil);

    /**
     * @dev Locks the account until a certain timestamp
     *
     * @param _lockedUntil The time at which this account will no longer be locked
     */
    function lock(uint256 _lockedUntil) external virtual {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        address _owner = _rootTokenOwner(chainId, tokenContract, tokenId);

        if (_owner == address(0)) revert NotAuthorized();
        if (msg.sender != _owner) revert NotAuthorized();

        if (_lockedUntil > block.timestamp + 365 days) {
            revert ExceedsMaxLockTime();
        }

        if (_lockedUntil < block.timestamp) {
            revert LockTimeInPast();
        }

        _beforeLock();

        lockedUntil = _lockedUntil;

        emit LockUpdated(false, _lockedUntil);
    }

    /**
     * @dev Locks the account until owner unlocks it
     */
    function softLock() external virtual {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        address _owner = _rootTokenOwner(chainId, tokenContract, tokenId);

        if (_owner == address(0)) revert NotAuthorized();
        if (msg.sender != _owner) revert NotAuthorized();

        _beforeLock();

        softLocked = true;

        emit LockUpdated(true, lockedUntil);
    }

    /**
     * @dev Unlocks the account when soft locked
     */
    function unlock() external virtual {
        // If the account is hard locked, the lock must expire or token ownership must change
        if (lockedUntil > block.timestamp) revert AccountTimeLocked();

        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        address _owner = _rootTokenOwner(chainId, tokenContract, tokenId);

        if (_owner == address(0)) revert NotAuthorized();
        if (msg.sender != _owner) revert NotAuthorized();

        _beforeUnlock();

        softLocked = false;

        emit LockUpdated(false, lockedUntil);
    }

    /**
     * @dev Called when the token associated with this account is transferred
     * token contract is responsible for only calling this function for a token with an account
     */
    function onAccountBearingTokenTransfer(uint256 _tokenId) external virtual {
        (, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();

        // Must be called by the token contract for the correct token
        if (_tokenId != tokenId) revert NotAuthorized();
        if (msg.sender != tokenContract) revert NotAuthorized();

        // If the account is hard locked, unlock it
        if (lockedUntil > block.timestamp) {
          lockedUntil = 0;
        }

        // If the account is soft locked, unlock it
        if (softLocked) {
          softLocked = false;
        }

        emit LockUpdated(false, 0);
    }

    /**
     * @dev Returns the current lock status of the account as a boolean
     */
    function isLocked() public view virtual returns (bool) {
        return softLocked || (lockedUntil > block.timestamp);
    }

    function isSoftLocked() public view virtual returns (bool) {
        return softLocked;
    }

    function isHardLocked() public view virtual returns (bool) {
        return lockedUntil > block.timestamp;
    }

    function lockInfo() public view virtual returns (bool, uint256) {
        return (softLocked, lockedUntil);
    }

    function _rootTokenOwner(uint256 chainId, address tokenContract, uint256 tokenId)
        internal
        view
        virtual
        returns (address);

    function _beforeLock() internal virtual {}
    function _beforeUnlock() internal virtual {}
}
