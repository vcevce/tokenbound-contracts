pragma solidity ^0.8.13;

// OpenZeppelin Contracts (last updated v4.9.0) (utils/Create2.sol)

/**
 * @dev Helper to make usage of the `CREATE2` EVM opcode easier and safer.
 * `CREATE2` can be used to compute in advance the address where a smart
 * contract will be deployed, which allows for interesting new mechanisms known
 * as 'counterfactual interactions'.
 *
 * See the https://eips.ethereum.org/EIPS/eip-1014#motivation[EIP] for more
 * information.
 */
library Create2 {
    /**
     * @dev Deploys a contract using `CREATE2`. The address where the contract
     * will be deployed can be known in advance via {computeAddress}.
     *
     * The bytecode for a contract can be obtained from Solidity with
     * `type(contractName).creationCode`.
     *
     * Requirements:
     *
     * - `bytecode` must not be empty.
     * - `salt` must have not been used for `bytecode` already.
     * - the factory must have a balance of at least `amount`.
     * - if `amount` is non-zero, `bytecode` must have a `payable` constructor.
     */
    function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) internal returns (address addr) {
        require(address(this).balance >= amount, "Create2: insufficient balance");
        require(bytecode.length != 0, "Create2: bytecode length is zero");
        /// @solidity memory-safe-assembly
        assembly {
            addr := create2(amount, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "Create2: Failed on deploy");
    }

    /**
     * @dev Returns the address where a contract will be stored if deployed via {deploy}. Any change in the
     * `bytecodeHash` or `salt` will result in a new destination address.
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash) internal view returns (address) {
        return computeAddress(salt, bytecodeHash, address(this));
    }

    /**
     * @dev Returns the address where a contract will be stored if deployed via {deploy} from a contract located at
     * `deployer`. If `deployer` is this contract's address, returns the same value as {computeAddress}.
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash, address deployer) internal pure returns (address addr) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40) // Get free memory pointer

            // |                   | ↓ ptr ...  ↓ ptr + 0x0B (start) ...  ↓ ptr + 0x20 ...  ↓ ptr + 0x40 ...   |
            // |-------------------|---------------------------------------------------------------------------|
            // | bytecodeHash      |                                                        CCCCCCCCCCCCC...CC |
            // | salt              |                                      BBBBBBBBBBBBB...BB                   |
            // | deployer          | 000000...0000AAAAAAAAAAAAAAAAAAA...AA                                     |
            // | 0xFF              |            FF                                                             |
            // |-------------------|---------------------------------------------------------------------------|
            // | memory            | 000000...00FFAAAAAAAAAAAAAAAAAAA...AABBBBBBBBBBBBB...BBCCCCCCCCCCCCC...CC |
            // | keccak(start, 85) |            ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑ |

            mstore(add(ptr, 0x40), bytecodeHash)
            mstore(add(ptr, 0x20), salt)
            mstore(ptr, deployer) // Right-aligned with 12 preceding garbage bytes
            let start := add(ptr, 0x0b) // The hashed data starts at the final garbage byte which we will set to 0xff
            mstore8(start, 0xff)
            addr := keccak256(start, 85)
        }
    }
}

// OpenZeppelin Contracts (last updated v4.9.0) (utils/Strings.sol)

// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/Math.sol)

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    enum Rounding {
        Down, // Toward negative infinity
        Up, // Toward infinity
        Zero // Toward zero
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow.
        return (a & b) + (a ^ b) / 2;
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds up instead
     * of rounding down.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b - 1) / b can overflow on addition, so we distribute.
        return a == 0 ? 0 : (a - 1) / b + 1;
    }

    /**
     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or denominator == 0
     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv)
     * with further edits by Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use
            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
            // variables such that product = prod1 * 2^256 + prod0.
            uint256 prod0; // Least significant 256 bits of the product
            uint256 prod1; // Most significant 256 bits of the product
            assembly {
                let mm := mulmod(x, y, not(0))
                prod0 := mul(x, y)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }

            // Handle non-overflow cases, 256 by 256 division.
            if (prod1 == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return prod0 / denominator;
            }

            // Make sure the result is less than 2^256. Also prevents denominator == 0.
            require(denominator > prod1, "Math: mulDiv overflow");

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [prod1 prod0].
            uint256 remainder;
            assembly {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator. Always >= 1.
            // See https://cs.stackexchange.com/q/138556/92363.

            // Does not overflow because the denominator cannot be zero at this stage in the function.
            uint256 twos = denominator & (~denominator + 1);
            assembly {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [prod1 prod0] by twos.
                prod0 := div(prod0, twos)

                // Flip twos such that it is 2^256 / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from prod1 into prod0.
            prod0 |= prod1 * twos;

            // Invert denominator mod 2^256. Now that denominator is an odd number, it has an inverse modulo 2^256 such
            // that denominator * inv = 1 mod 2^256. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv = 1 mod 2^4.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also works
            // in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2^8
            inverse *= 2 - denominator * inverse; // inverse mod 2^16
            inverse *= 2 - denominator * inverse; // inverse mod 2^32
            inverse *= 2 - denominator * inverse; // inverse mod 2^64
            inverse *= 2 - denominator * inverse; // inverse mod 2^128
            inverse *= 2 - denominator * inverse; // inverse mod 2^256

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2^256. Since the preconditions guarantee that the outcome is
            // less than 2^256, this is the final result. We don't need to compute the high bits of the result and prod1
            // is no longer required.
            result = prod0 * inverse;
            return result;
        }
    }

    /**
     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        uint256 result = mulDiv(x, y, denominator);
        if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {
            result += 1;
        }
        return result;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded down.
     *
     * Inspired by Henry S. Warren, Jr.'s "Hacker's Delight" (Chapter 11).
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        // For our first guess, we get the biggest power of 2 which is smaller than the square root of the target.
        //
        // We know that the "msb" (most significant bit) of our target number `a` is a power of 2 such that we have
        // `msb(a) <= a < 2*msb(a)`. This value can be written `msb(a)=2**k` with `k=log2(a)`.
        //
        // This can be rewritten `2**log2(a) <= a < 2**(log2(a) + 1)`
        // → `sqrt(2**k) <= sqrt(a) < sqrt(2**(k+1))`
        // → `2**(k/2) <= sqrt(a) < 2**((k+1)/2) <= 2**(k/2 + 1)`
        //
        // Consequently, `2**(log2(a) / 2)` is a good first approximation of `sqrt(a)` with at least 1 correct bit.
        uint256 result = 1 << (log2(a) >> 1);

        // At this point `result` is an estimation with one bit of precision. We know the true value is a uint128,
        // since it is the square root of a uint256. Newton's method converges quadratically (precision doubles at
        // every iteration). We thus need at most 7 iteration to turn our partial result with one bit of precision
        // into the expected uint128 result.
        unchecked {
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            return min(result, a / result);
        }
    }

    /**
     * @notice Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + (rounding == Rounding.Up && result * result < a ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 2, rounded down, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 128;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 64;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 32;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 16;
            }
            if (value >> 8 > 0) {
                value >>= 8;
                result += 8;
            }
            if (value >> 4 > 0) {
                value >>= 4;
                result += 4;
            }
            if (value >> 2 > 0) {
                value >>= 2;
                result += 2;
            }
            if (value >> 1 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + (rounding == Rounding.Up && 1 << result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 10, rounded down, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + (rounding == Rounding.Up && 10 ** result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 256, rounded down, of a positive value.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 16;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 8;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 4;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 2;
            }
            if (value >> 8 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + (rounding == Rounding.Up && 1 << (result << 3) < value ? 1 : 0);
        }
    }
}

// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/SignedMath.sol)

/**
 * @dev Standard signed math utilities missing in the Solidity language.
 */
library SignedMath {
    /**
     * @dev Returns the largest of two signed numbers.
     */
    function max(int256 a, int256 b) internal pure returns (int256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two signed numbers.
     */
    function min(int256 a, int256 b) internal pure returns (int256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two signed numbers without overflow.
     * The result is rounded towards zero.
     */
    function average(int256 a, int256 b) internal pure returns (int256) {
        // Formula from the book "Hacker's Delight"
        int256 x = (a & b) + ((a ^ b) >> 1);
        return x + (int256(uint256(x) >> 255) & (a ^ b));
    }

    /**
     * @dev Returns the absolute unsigned value of a signed value.
     */
    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            // must be unchecked in order to support `n = type(int256).min`
            return uint256(n >= 0 ? n : -n);
        }
    }
}

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";
    uint8 private constant _ADDRESS_LENGTH = 20;

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            /// @solidity memory-safe-assembly
            assembly {
                ptr := add(buffer, add(32, length))
            }
            while (true) {
                ptr--;
                /// @solidity memory-safe-assembly
                assembly {
                    mstore8(ptr, byte(mod(value, 10), _SYMBOLS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }

    /**
     * @dev Converts a `int256` to its ASCII `string` decimal representation.
     */
    function toString(int256 value) internal pure returns (string memory) {
        return string(abi.encodePacked(value < 0 ? "-" : "", toString(SignedMath.abs(value))));
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, Math.log256(value) + 1);
        }
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);
    }

    /**
     * @dev Returns true if the two strings are equal.
     */
    function equal(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}

// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable2Step.sol)

// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)

// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

/**
 * @dev Contract module which provides access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership} and {acceptOwnership}.
 *
 * This module is used through inheritance. It will make available all functions
 * from parent (Ownable).
 */
abstract contract Ownable2Step is Ownable {
    address private _pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Returns the address of the pending owner.
     */
    function pendingOwner() public view virtual returns (address) {
        return _pendingOwner;
    }

    /**
     * @dev Starts the ownership transfer of the contract to a new account. Replaces the pending transfer if there is one.
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual override onlyOwner {
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner(), newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`) and deletes any pending owner.
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual override {
        delete _pendingOwner;
        super._transferOwnership(newOwner);
    }

    /**
     * @dev The new owner accepts the ownership transfer.
     */
    function acceptOwnership() public virtual {
        address sender = _msgSender();
        require(pendingOwner() == sender, "Ownable2Step: caller is not the new owner");
        _transferOwnership(sender);
    }
}

/**
 * @dev Manages upgrade and cross-chain execution settings for accounts
 */
contract AccountGuardian is Ownable2Step {
    /**
     * @dev mapping from implementation => is trusted
     */
    mapping(address => bool) public isTrustedImplementation;

    /**
     * @dev mapping from cross-chain executor => is trusted
     */
    mapping(address => bool) public isTrustedExecutor;

    event TrustedImplementationUpdated(address implementation, bool trusted);
    event TrustedExecutorUpdated(address executor, bool trusted);

    constructor(address owner) {
        _transferOwnership(owner);
    }

    /**
     * @dev Sets a given implementation address as trusted, allowing accounts to upgrade to this
     * implementation
     */
    function setTrustedImplementation(address implementation, bool trusted) external onlyOwner {
        isTrustedImplementation[implementation] = trusted;
        emit TrustedImplementationUpdated(implementation, trusted);
    }

    /**
     * @dev Sets a given cross-chain executor address as trusted, allowing it to relay operations to
     * accounts on non-native chains
     */
    function setTrustedExecutor(address executor, bool trusted) external onlyOwner {
        isTrustedExecutor[executor] = trusted;
        emit TrustedExecutorUpdated(executor, trusted);
    }
}

// OpenZeppelin Contracts (last updated v4.9.0) (proxy/utils/UUPSUpgradeable.sol)

// OpenZeppelin Contracts (last updated v4.5.0) (interfaces/draft-IERC1822.sol)

/**
 * @dev ERC1822: Universal Upgradeable Proxy Standard (UUPS) documents a method for upgradeability through a simplified
 * proxy whose upgrades are fully controlled by the current implementation.
 */
interface IERC1822Proxiable {
    /**
     * @dev Returns the storage slot that the proxiable contract assumes is being used to store the implementation
     * address.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy.
     */
    function proxiableUUID() external view returns (bytes32);
}

// OpenZeppelin Contracts (last updated v4.9.0) (proxy/ERC1967/ERC1967Upgrade.sol)

// OpenZeppelin Contracts v4.4.1 (proxy/beacon/IBeacon.sol)

/**
 * @dev This is the interface that {BeaconProxy} expects of its beacon.
 */
interface IBeacon {
    /**
     * @dev Must return an address that can be used as a delegate call target.
     *
     * {BeaconProxy} will check that this address is a contract.
     */
    function implementation() external view returns (address);
}

// OpenZeppelin Contracts (last updated v4.9.0) (interfaces/IERC1967.sol)

/**
 * @dev ERC-1967: Proxy Storage Slots. This interface contains the events defined in the ERC.
 *
 * _Available since v4.8.3._
 */
interface IERC1967 {
    /**
     * @dev Emitted when the implementation is upgraded.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Emitted when the admin account has changed.
     */
    event AdminChanged(address previousAdmin, address newAdmin);

    /**
     * @dev Emitted when the beacon is changed.
     */
    event BeaconUpgraded(address indexed beacon);
}

// OpenZeppelin Contracts (last updated v4.9.0) (utils/Address.sol)

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     *
     * Furthermore, `isContract` will also return true if the target contract within
     * the same transaction is already scheduled for destruction by `SELFDESTRUCT`,
     * which only has an effect at the end of a transaction.
     * ====
     *
     * [IMPORTANT]
     * ====
     * You shouldn't rely on `isContract` to protect against flash loan attacks!
     *
     * Preventing calls from contracts is highly discouraged. It breaks composability, breaks support for smart wallets
     * like Gnosis Safe, and does not provide security since it can be circumvented by calling from a contract
     * constructor.
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.

        return account.code.length > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.8.0/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verify that a low level call to smart-contract was successful, and revert (either by bubbling
     * the revert reason or using the provided one) in case of unsuccessful call or if target was not a contract.
     *
     * _Available since v4.8._
     */
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        if (success) {
            if (returndata.length == 0) {
                // only check isContract if the call was successful and the return data is empty
                // otherwise we already know that it was a contract
                require(isContract(target), "Address: call to non-contract");
            }
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    /**
     * @dev Tool to verify that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason or using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    function _revert(bytes memory returndata, string memory errorMessage) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            /// @solidity memory-safe-assembly
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert(errorMessage);
        }
    }
}

// OpenZeppelin Contracts (last updated v4.9.0) (utils/StorageSlot.sol)
// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.

/**
 * @dev Library for reading and writing primitive types to specific storage slots.
 *
 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.
 * This library helps with reading and writing to such slots without the need for inline assembly.
 *
 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.
 *
 * Example usage to set ERC1967 implementation slot:
 * ```solidity
 * contract ERC1967 {
 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 *
 *     function _getImplementation() internal view returns (address) {
 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
 *     }
 *
 *     function _setImplementation(address newImplementation) internal {
 *         require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");
 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
 *     }
 * }
 * ```
 *
 * _Available since v4.1 for `address`, `bool`, `bytes32`, `uint256`._
 * _Available since v4.9 for `string`, `bytes`._
 */
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    struct BooleanSlot {
        bool value;
    }

    struct Bytes32Slot {
        bytes32 value;
    }

    struct Uint256Slot {
        uint256 value;
    }

    struct StringSlot {
        string value;
    }

    struct BytesSlot {
        bytes value;
    }

    /**
     * @dev Returns an `AddressSlot` with member `value` located at `slot`.
     */
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BooleanSlot` with member `value` located at `slot`.
     */
    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Bytes32Slot` with member `value` located at `slot`.
     */
    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Uint256Slot` with member `value` located at `slot`.
     */
    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` with member `value` located at `slot`.
     */
    function getStringSlot(bytes32 slot) internal pure returns (StringSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` representation of the string storage pointer `store`.
     */
    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := store.slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` with member `value` located at `slot`.
     */
    function getBytesSlot(bytes32 slot) internal pure returns (BytesSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` representation of the bytes storage pointer `store`.
     */
    function getBytesSlot(bytes storage store) internal pure returns (BytesSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := store.slot
        }
    }
}

/**
 * @dev This abstract contract provides getters and event emitting update functions for
 * https://eips.ethereum.org/EIPS/eip-1967[EIP1967] slots.
 *
 * _Available since v4.1._
 */
abstract contract ERC1967Upgrade is IERC1967 {
    // This is the keccak-256 hash of "eip1967.proxy.rollback" subtracted by 1
    bytes32 private constant _ROLLBACK_SLOT = 0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143;

    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev Returns the current implementation address.
     */
    function _getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
    }

    /**
     * @dev Perform implementation upgrade
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeTo(address newImplementation) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Perform implementation upgrade with additional setup call.
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeToAndCall(address newImplementation, bytes memory data, bool forceCall) internal {
        _upgradeTo(newImplementation);
        if (data.length > 0 || forceCall) {
            Address.functionDelegateCall(newImplementation, data);
        }
    }

    /**
     * @dev Perform implementation upgrade with security checks for UUPS proxies, and additional setup call.
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeToAndCallUUPS(address newImplementation, bytes memory data, bool forceCall) internal {
        // Upgrades from old implementations will perform a rollback test. This test requires the new
        // implementation to upgrade back to the old, non-ERC1822 compliant, implementation. Removing
        // this special case will break upgrade paths from old UUPS implementation to new ones.
        if (StorageSlot.getBooleanSlot(_ROLLBACK_SLOT).value) {
            _setImplementation(newImplementation);
        } else {
            try IERC1822Proxiable(newImplementation).proxiableUUID() returns (bytes32 slot) {
                require(slot == _IMPLEMENTATION_SLOT, "ERC1967Upgrade: unsupported proxiableUUID");
            } catch {
                revert("ERC1967Upgrade: new implementation is not UUPS");
            }
            _upgradeToAndCall(newImplementation, data, forceCall);
        }
    }

    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev Returns the current admin.
     */
    function _getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(_ADMIN_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 admin slot.
     */
    function _setAdmin(address newAdmin) private {
        require(newAdmin != address(0), "ERC1967: new admin is the zero address");
        StorageSlot.getAddressSlot(_ADMIN_SLOT).value = newAdmin;
    }

    /**
     * @dev Changes the admin of the proxy.
     *
     * Emits an {AdminChanged} event.
     */
    function _changeAdmin(address newAdmin) internal {
        emit AdminChanged(_getAdmin(), newAdmin);
        _setAdmin(newAdmin);
    }

    /**
     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.
     * This is bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)) and is validated in the constructor.
     */
    bytes32 internal constant _BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /**
     * @dev Returns the current beacon.
     */
    function _getBeacon() internal view returns (address) {
        return StorageSlot.getAddressSlot(_BEACON_SLOT).value;
    }

    /**
     * @dev Stores a new beacon in the EIP1967 beacon slot.
     */
    function _setBeacon(address newBeacon) private {
        require(Address.isContract(newBeacon), "ERC1967: new beacon is not a contract");
        require(
            Address.isContract(IBeacon(newBeacon).implementation()),
            "ERC1967: beacon implementation is not a contract"
        );
        StorageSlot.getAddressSlot(_BEACON_SLOT).value = newBeacon;
    }

    /**
     * @dev Perform beacon upgrade with additional setup call. Note: This upgrades the address of the beacon, it does
     * not upgrade the implementation contained in the beacon (see {UpgradeableBeacon-_setImplementation} for that).
     *
     * Emits a {BeaconUpgraded} event.
     */
    function _upgradeBeaconToAndCall(address newBeacon, bytes memory data, bool forceCall) internal {
        _setBeacon(newBeacon);
        emit BeaconUpgraded(newBeacon);
        if (data.length > 0 || forceCall) {
            Address.functionDelegateCall(IBeacon(newBeacon).implementation(), data);
        }
    }
}

/**
 * @dev An upgradeability mechanism designed for UUPS proxies. The functions included here can perform an upgrade of an
 * {ERC1967Proxy}, when this contract is set as the implementation behind such a proxy.
 *
 * A security mechanism ensures that an upgrade does not turn off upgradeability accidentally, although this risk is
 * reinstated if the upgrade retains upgradeability but removes the security mechanism, e.g. by replacing
 * `UUPSUpgradeable` with a custom implementation of upgrades.
 *
 * The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.
 *
 * _Available since v4.1._
 */
abstract contract UUPSUpgradeable is IERC1822Proxiable, ERC1967Upgrade {
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable state-variable-assignment
    address private immutable __self = address(this);

    /**
     * @dev Check that the execution is being performed through a delegatecall call and that the execution context is
     * a proxy contract with an implementation (as defined in ERC1967) pointing to self. This should only be the case
     * for UUPS and transparent proxies that are using the current contract as their implementation. Execution of a
     * function through ERC1167 minimal proxies (clones) would not normally pass this test, but is not guaranteed to
     * fail.
     */
    modifier onlyProxy() {
        require(address(this) != __self, "Function must be called through delegatecall");
        require(_getImplementation() == __self, "Function must be called through active proxy");
        _;
    }

    /**
     * @dev Check that the execution is not being performed through a delegate call. This allows a function to be
     * callable on the implementing contract but not through proxies.
     */
    modifier notDelegated() {
        require(address(this) == __self, "UUPSUpgradeable: must not be called through delegatecall");
        _;
    }

    /**
     * @dev Implementation of the ERC1822 {proxiableUUID} function. This returns the storage slot used by the
     * implementation. It is used to validate the implementation's compatibility when performing an upgrade.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy. This is guaranteed by the `notDelegated` modifier.
     */
    function proxiableUUID() external view virtual override notDelegated returns (bytes32) {
        return _IMPLEMENTATION_SLOT;
    }

    /**
     * @dev Upgrade the implementation of the proxy to `newImplementation`.
     *
     * Calls {_authorizeUpgrade}.
     *
     * Emits an {Upgraded} event.
     *
     * @custom:oz-upgrades-unsafe-allow-reachable delegatecall
     */
    function upgradeTo(address newImplementation) public virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, new bytes(0), false);
    }

    /**
     * @dev Upgrade the implementation of the proxy to `newImplementation`, and subsequently execute the function call
     * encoded in `data`.
     *
     * Calls {_authorizeUpgrade}.
     *
     * Emits an {Upgraded} event.
     *
     * @custom:oz-upgrades-unsafe-allow-reachable delegatecall
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) public payable virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data, true);
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
     * {upgradeTo} and {upgradeToAndCall}.
     *
     * Normally, this function will use an xref:access.adoc[access control] modifier such as {Ownable-onlyOwner}.
     *
     * ```solidity
     * function _authorizeUpgrade(address) internal override onlyOwner {}
     * ```
     */
    function _authorizeUpgrade(address newImplementation) internal virtual;
}

// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/SignatureChecker.sol)

// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/ECDSA.sol)

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV // Deprecated in v4.8
    }

    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature` or error string. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            /// @solidity memory-safe-assembly
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address, RecoverError) {
        bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        uint8 v = uint8((uint256(vs) >> 255) + 27);
        return tryRecover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     *
     * _Available since v4.2._
     */
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address, RecoverError) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }

        return (signer, RecoverError.NoError);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 message) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32")
            mstore(0x1c, hash)
            message := keccak256(0x00, 0x3c)
        }
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from `s`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(s.length), s));
    }

    /**
     * @dev Returns an Ethereum Signed Typed Data, created from a
     * `domainSeparator` and a `structHash`. This produces hash corresponding
     * to the one signed with the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
     * JSON-RPC method as part of EIP-712.
     *
     * See {recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 data) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            data := keccak256(ptr, 0x42)
        }
    }

    /**
     * @dev Returns an Ethereum Signed Data with intended validator, created from a
     * `validator` and `data` according to the version 0 of EIP-191.
     *
     * See {recover}.
     */
    function toDataWithIntendedValidatorHash(address validator, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x00", validator, data));
    }
}

// OpenZeppelin Contracts v4.4.1 (interfaces/IERC1271.sol)

/**
 * @dev Interface of the ERC1271 standard signature validation method for
 * contracts as defined in https://eips.ethereum.org/EIPS/eip-1271[ERC-1271].
 *
 * _Available since v4.1._
 */
interface IERC1271 {
    /**
     * @dev Should return whether the signature provided is valid for the provided data
     * @param hash      Hash of the data to be signed
     * @param signature Signature byte array associated with _data
     */
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
}

/**
 * @dev Signature verification helper that can be used instead of `ECDSA.recover` to seamlessly support both ECDSA
 * signatures from externally owned accounts (EOAs) as well as ERC1271 signatures from smart contract wallets like
 * Argent and Gnosis Safe.
 *
 * _Available since v4.1._
 */
library SignatureChecker {
    /**
     * @dev Checks if a signature is valid for a given signer and data hash. If the signer is a smart contract, the
     * signature is validated against that smart contract using ERC1271, otherwise it's validated using `ECDSA.recover`.
     *
     * NOTE: Unlike ECDSA signatures, contract signatures are revocable, and the outcome of this function can thus
     * change through time. It could return true at block N and false at block N+1 (or the opposite).
     */
    function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature) internal view returns (bool) {
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(hash, signature);
        return
            (error == ECDSA.RecoverError.NoError && recovered == signer) ||
            isValidERC1271SignatureNow(signer, hash, signature);
    }

    /**
     * @dev Checks if a signature is valid for a given signer and data hash. The signature is validated
     * against the signer smart contract using ERC1271.
     *
     * NOTE: Unlike ECDSA signatures, contract signatures are revocable, and the outcome of this function can thus
     * change through time. It could return true at block N and false at block N+1 (or the opposite).
     */
    function isValidERC1271SignatureNow(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
        );
        return (success &&
            result.length >= 32 &&
            abi.decode(result, (bytes32)) == bytes32(IERC1271.isValidSignature.selector));
    }
}

// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC721/utils/ERC721Holder.sol)

// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC721/IERC721Receiver.sol)

/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
interface IERC721Receiver {
    /**
     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}
     * by `operator` from `from`, this function is called.
     *
     * It must return its Solidity selector to confirm the token transfer.
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.
     *
     * The selector can be obtained in Solidity with `IERC721Receiver.onERC721Received.selector`.
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

/**
 * @dev Implementation of the {IERC721Receiver} interface.
 *
 * Accepts all token transfers.
 * Make sure the contract is able to use its token with {IERC721-safeTransferFrom}, {IERC721-approve} or {IERC721-setApprovalForAll}.
 */
contract ERC721Holder is IERC721Receiver {
    /**
     * @dev See {IERC721Receiver-onERC721Received}.
     *
     * Always returns `IERC721Receiver.onERC721Received.selector`.
     */
    function onERC721Received(address, address, uint256, bytes memory) public virtual override returns (bytes4) {
        return this.onERC721Received.selector;
    }
}

// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC1155/utils/ERC1155Holder.sol)

// OpenZeppelin Contracts v4.4.1 (token/ERC1155/utils/ERC1155Receiver.sol)

// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC1155/IERC1155Receiver.sol)

// OpenZeppelin Contracts v4.4.1 (utils/introspection/IERC165.sol)

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

/**
 * @dev _Available since v3.1._
 */
interface IERC1155Receiver is IERC165 {
    /**
     * @dev Handles the receipt of a single ERC1155 token type. This function is
     * called at the end of a `safeTransferFrom` after the balance has been updated.
     *
     * NOTE: To accept the transfer, this must return
     * `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`
     * (i.e. 0xf23a6e61, or its own function selector).
     *
     * @param operator The address which initiated the transfer (i.e. msg.sender)
     * @param from The address which previously owned the token
     * @param id The ID of the token being transferred
     * @param value The amount of tokens being transferred
     * @param data Additional data with no specified format
     * @return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))` if transfer is allowed
     */
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);

    /**
     * @dev Handles the receipt of a multiple ERC1155 token types. This function
     * is called at the end of a `safeBatchTransferFrom` after the balances have
     * been updated.
     *
     * NOTE: To accept the transfer(s), this must return
     * `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`
     * (i.e. 0xbc197c81, or its own function selector).
     *
     * @param operator The address which initiated the batch transfer (i.e. msg.sender)
     * @param from The address which previously owned the token
     * @param ids An array containing ids of each token being transferred (order and length must match values array)
     * @param values An array containing amounts of each token being transferred (order and length must match ids array)
     * @param data Additional data with no specified format
     * @return `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))` if transfer is allowed
     */
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}

// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 *
 * Alternatively, {ERC165Storage} provides an easier to use but more expensive implementation.
 */
abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

/**
 * @dev _Available since v3.1._
 */
abstract contract ERC1155Receiver is ERC165, IERC1155Receiver {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId || super.supportsInterface(interfaceId);
    }
}

/**
 * Simple implementation of `ERC1155Receiver` that will allow a contract to hold ERC1155 tokens.
 *
 * IMPORTANT: When inheriting this contract, you must include a way to use the received tokens, otherwise they will be
 * stuck.
 *
 * @dev _Available since v3.1._
 */
contract ERC1155Holder is ERC1155Receiver {
    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes memory
    ) public virtual override returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public virtual override returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }
}

library ERC6551BytecodeLib {
    /**
     * @dev Returns the creation code of the token bound account for a non-fungible token.
     *
     * @return result The creation code of the token bound account
     */
    function getCreationCode(
        address implementation,
        bytes32 salt,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId
    ) internal pure returns (bytes memory result) {
        assembly {
            result := mload(0x40) // Grab the free memory pointer
            // Layout the variables and bytecode backwards
            mstore(add(result, 0xb7), tokenId)
            mstore(add(result, 0x97), shr(96, shl(96, tokenContract)))
            mstore(add(result, 0x77), chainId)
            mstore(add(result, 0x57), salt)
            mstore(add(result, 0x37), 0x5af43d82803e903d91602b57fd5bf3)
            mstore(add(result, 0x28), implementation)
            mstore(add(result, 0x14), 0x3d60ad80600a3d3981f3363d3d373d3d3d363d73)
            mstore(result, 0xb7) // Store the length
            mstore(0x40, add(result, 0xd7)) // Allocate the memory
        }
    }

    /**
     * @dev Returns the create2 address computed from `salt`, `bytecodeHash`, `deployer`.
     *
     * @return result The create2 address computed from `salt`, `bytecodeHash`, `deployer`
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash, address deployer)
        internal
        pure
        returns (address result)
    {
        assembly {
            result := mload(0x40) // Grab the free memory pointer
            mstore8(result, 0xff)
            mstore(add(result, 0x35), bytecodeHash)
            mstore(add(result, 0x01), shl(96, deployer))
            mstore(add(result, 0x15), salt)
            result := keccak256(result, 0x55)
        }
    }
}

library ERC6551AccountLib {
    function computeAddress(
        address registry,
        address _implementation,
        bytes32 _salt,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId
    ) internal pure returns (address) {
        bytes32 bytecodeHash = keccak256(
            ERC6551BytecodeLib.getCreationCode(
                _implementation, _salt, chainId, tokenContract, tokenId
            )
        );

        return Create2.computeAddress(_salt, bytecodeHash, registry);
    }

    function isERC6551Account(address account, address expectedImplementation, address registry)
        internal
        view
        returns (bool)
    {
        // invalid bytecode size
        if (account.code.length != 0xAD) return false;

        address _implementation = implementation(account);

        // implementation does not exist
        if (_implementation.code.length == 0) return false;

        // invalid implementation
        if (_implementation != expectedImplementation) return false;

        (bytes32 _salt, uint256 chainId, address tokenContract, uint256 tokenId) = context(account);

        return account
            == computeAddress(registry, _implementation, _salt, chainId, tokenContract, tokenId);
    }

    function implementation(address account) internal view returns (address _implementation) {
        assembly {
            // copy proxy implementation (0x14 bytes)
            extcodecopy(account, 0xC, 0xA, 0x14)
            _implementation := mload(0x00)
        }
    }

    function implementation() internal view returns (address _implementation) {
        return implementation(address(this));
    }

    function token(address account) internal view returns (uint256, address, uint256) {
        bytes memory encodedData = new bytes(0x60);

        assembly {
            // copy 0x60 bytes from end of context
            extcodecopy(account, add(encodedData, 0x20), 0x4d, 0x60)
        }

        return abi.decode(encodedData, (uint256, address, uint256));
    }

    function token() internal view returns (uint256, address, uint256) {
        return token(address(this));
    }

    function salt(address account) internal view returns (bytes32) {
        bytes memory encodedData = new bytes(0x20);

        assembly {
            // copy 0x20 bytes from beginning of context
            extcodecopy(account, add(encodedData, 0x20), 0x2d, 0x20)
        }

        return abi.decode(encodedData, (bytes32));
    }

    function salt() internal view returns (bytes32) {
        return salt(address(this));
    }

    function context(address account) internal view returns (bytes32, uint256, address, uint256) {
        bytes memory encodedData = new bytes(0x80);

        assembly {
            // copy full context (0x80 bytes)
            extcodecopy(account, add(encodedData, 0x20), 0x2D, 0x80)
        }

        return abi.decode(encodedData, (bytes32, uint256, address, uint256));
    }

    function context() internal view returns (bytes32, uint256, address, uint256) {
        return context(address(this));
    }
}

error InvalidOperation();
error ContractCreationFailed();
error NotAuthorized();
error InvalidInput();
error ExceedsMaxLockTime();
error LockTimeInPast();
error AccountLocked();
error AccountUnlocked();
error AccountTimeLocked();
error InvalidAccountProof();
error InvalidGuardian();
error InvalidImplementation();
error AlreadyInitialized();
error InvalidEntryPoint();
error InvalidMulticallForwarder();
error InvalidERC6551Registry();
error OwnershipCycle();

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

library LibSandbox {
    bytes public constant header = hex"604380600d600039806000f3fe73";
    bytes public constant footer =
        hex"3314601d573d3dfd5b363d3d373d3d6014360360143d5160601c5af43d6000803e80603e573d6000fd5b3d6000f3";

    function bytecode(address owner) internal pure returns (bytes memory) {
        return abi.encodePacked(header, owner, footer);
    }

    function sandbox(address owner) internal view returns (address) {
        return
            Create2.computeAddress(keccak256("org.tokenbound.sandbox"), keccak256(bytecode(owner)));
    }

    function deploy(address owner) internal {
        Create2.deploy(0, keccak256("org.tokenbound.sandbox"), bytecode(owner));
    }
}

/**
 * @title Account Overrides
 * @dev Allows the root owner of a token bound account to override the implementation of a given
 * function selector on the account. Overrides are keyed by the root owner address, so will be
 * disabled upon transfer of the token which owns this account tree.
 */
abstract contract Overridable {
    /**
     * @dev mapping from owner => selector => implementation
     */
    mapping(address => mapping(bytes4 => address)) public overrides;

    event OverrideUpdated(address owner, bytes4 selector, address implementation);

    /**
     * @dev Sets the implementation address for a given array of function selectors. Can only be
     * called by the root owner of the account
     *
     * @param selectors Array of selectors to override
     * @param implementations Array of implementation address corresponding to selectors
     */
    function setOverrides(bytes4[] calldata selectors, address[] calldata implementations)
        external
        virtual
    {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        address _owner = _rootTokenOwner(chainId, tokenContract, tokenId);

        if (_owner == address(0)) revert NotAuthorized();
        if (msg.sender != _owner) revert NotAuthorized();

        _beforeSetOverrides();

        address sandbox = LibSandbox.sandbox(address(this));
        if (sandbox.code.length == 0) LibSandbox.deploy(address(this));

        uint256 length = selectors.length;

        if (implementations.length != length) revert InvalidInput();

        for (uint256 i = 0; i < length; i++) {
            overrides[_owner][selectors[i]] = implementations[i];
            emit OverrideUpdated(_owner, selectors[i], implementations[i]);
        }
    }

    /**
     * @dev Calls into the implementation address using sandbox if override is set for the current
     * function selector. If an implementation is defined, this funciton will either revert or
     * return with the return value of the implementation
     */
    function _handleOverride() internal virtual {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        address _owner = _rootTokenOwner(chainId, tokenContract, tokenId);

        address implementation = overrides[_owner][msg.sig];

        if (implementation != address(0)) {
            address sandbox = LibSandbox.sandbox(address(this));
            (bool success, bytes memory result) =
                sandbox.call(abi.encodePacked(implementation, msg.data, msg.sender));
            assembly {
                if iszero(success) { revert(add(result, 32), mload(result)) }
                return(add(result, 32), mload(result))
            }
        }
    }

    /**
     * @dev Static calls into the implementation addressif override is set for the current function
     * selector. If an implementation is defined, this funciton will either revert or return with
     * the return value of the implementation
     */
    function _handleOverrideStatic() internal view virtual {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        address _owner = _rootTokenOwner(chainId, tokenContract, tokenId);

        address implementation = overrides[_owner][msg.sig];

        if (implementation != address(0)) {
            (bool success, bytes memory result) = implementation.staticcall(msg.data);
            assembly {
                if iszero(success) { revert(add(result, 32), mload(result)) }
                return(add(result, 32), mload(result))
            }
        }
    }

    function _beforeSetOverrides() internal virtual {}

    function _rootTokenOwner(uint256 chainId, address tokenContract, uint256 tokenId)
        internal
        view
        virtual
        returns (address);
}

/**
 * @title Account Permissions
 * @dev Allows the root owner of a token bound account to allow another account to execute
 * operations from this account. Permissions are keyed by the root owner address, so will be
 * disabled upon transfer of the token which owns this account tree.
 */
abstract contract Permissioned {
    /**
     * @dev mapping from owner => caller => has permissions
     */
    mapping(address => mapping(address => bool)) public permissions;

    event PermissionUpdated(address owner, address caller, bool hasPermission);

    /**
     * @dev Grants or revokes execution permissions for a given array of callers on this account.
     * Can only be called by the root owner of the account
     *
     * @param callers Array of callers to grant permissions to
     * @param _permissions Array of booleans, true if execution permissions should be granted,
     * false if permissions should be revoked
     */
    function setPermissions(address[] calldata callers, bool[] calldata _permissions)
        external
        virtual
    {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        address _owner = _rootTokenOwner(chainId, tokenContract, tokenId);

        if (_owner == address(0)) revert NotAuthorized();
        if (msg.sender != _owner) revert NotAuthorized();

        _beforeSetPermissions();

        uint256 length = callers.length;

        if (_permissions.length != length) revert InvalidInput();

        for (uint256 i = 0; i < length; i++) {
            permissions[_owner][callers[i]] = _permissions[i];
            emit PermissionUpdated(_owner, callers[i], _permissions[i]);
        }
    }

    /**
     * @dev Returns true if caller has permissions to act on behalf of owner
     *
     * @param caller Address to query permissions for
     * @param owner Root owner address for which to query permissions
     */
    function hasPermission(address caller, address owner) internal view returns (bool) {
        return permissions[owner][caller];
    }

    function _beforeSetPermissions() internal virtual {}

    function _rootTokenOwner(uint256 chainId, address tokenContract, uint256 tokenId)
        internal
        view
        virtual
        returns (address);
}

// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC721/IERC721.sol)

/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Note that the caller is responsible to confirm that the recipient is capable of receiving ERC721
     * or else they may be permanently lost. Usage of {safeTransferFrom} prevents loss, though the caller must
     * understand this adds an external call which potentially creates a reentrancy vulnerability.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

/// @dev the ERC-165 identifier for this interface is `0x6faff5f1`
interface IERC6551Account {
    /**
     * @dev Allows the account to receive Ether.
     *
     * Accounts MUST implement a `receive` function.
     *
     * Accounts MAY perform arbitrary logic to restrict conditions
     * under which Ether can be received.
     */
    receive() external payable;

    /**
     * @dev Returns the identifier of the non-fungible token which owns the account.
     *
     * The return value of this function MUST be constant - it MUST NOT change over time.
     *
     * @return chainId       The EIP-155 ID of the chain the token exists on
     * @return tokenContract The contract address of the token
     * @return tokenId       The ID of the token
     */
    function token()
        external
        view
        returns (uint256 chainId, address tokenContract, uint256 tokenId);

    /**
     * @dev Returns a value that SHOULD be modified each time the account changes state.
     *
     * @return The current account state
     */
    function state() external view returns (uint256);

    /**
     * @dev Returns a magic value indicating whether a given signer is authorized to act on behalf
     * of the account.
     *
     * MUST return the bytes4 magic value 0x523e3260 if the given signer is valid.
     *
     * By default, the holder of the non-fungible token the account is bound to MUST be considered
     * a valid signer.
     *
     * Accounts MAY implement additional authorization logic which invalidates the holder as a
     * signer or grants signing permissions to other non-holder accounts.
     *
     * @param  signer     The address to check signing authorization for
     * @param  context    Additional data used to determine whether the signer is valid
     * @return magicValue Magic value indicating whether the signer is valid
     */
    function isValidSigner(address signer, bytes calldata context)
        external
        view
        returns (bytes4 magicValue);
}

/**
 * @title Signatory
 * @dev Implements ERC-1271 signature verification
 */
abstract contract Signatory is IERC1271 {
    /**
     * @dev See {IERC1721-isValidSignature}
     */
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4 magicValue)
    {
        if (_isValidSignature(hash, signature)) {
            return IERC1271.isValidSignature.selector;
        }

        return bytes4(0);
    }

    function _isValidSignature(bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        returns (bool);
}

/**
 * @title ERC-6551 Account Support
 * @dev Implements the ERC-6551 Account interface
 */
abstract contract ERC6551Account is IERC6551Account, ERC165, Signatory {
    uint256 _state;

    receive() external payable virtual {}

    /**
     * @dev See: {IERC6551Account-isValidSigner}
     */
    function isValidSigner(address signer, bytes calldata data)
        external
        view
        returns (bytes4 magicValue)
    {
        if (_isValidSigner(signer, data)) {
            return IERC6551Account.isValidSigner.selector;
        }

        return bytes4(0);
    }

    /**
     * @dev See: {IERC6551Account-token}
     */
    function token()
        public
        view
        returns (uint256 chainId, address tokenContract, uint256 tokenId)
    {
        return ERC6551AccountLib.token();
    }

    /**
     * @dev See: {IERC6551Account-state}
     */
    function state() public view returns (uint256) {
        return _state;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return
            interfaceId == type(IERC6551Account).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns true if a given signer is authorized to use this account
     */
    function _isValidSigner(address signer, bytes memory) internal view virtual returns (bool);
}

// OpenZeppelin Contracts (last updated v4.9.3) (metatx/ERC2771Context.sol)

/**
 * @dev Context variant with ERC2771 support.
 */
abstract contract ERC2771Context is Context {
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address private immutable _trustedForwarder;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address trustedForwarder) {
        _trustedForwarder = trustedForwarder;
    }

    function isTrustedForwarder(address forwarder) public view virtual returns (bool) {
        return forwarder == _trustedForwarder;
    }

    function _msgSender() internal view virtual override returns (address sender) {
        if (isTrustedForwarder(msg.sender) && msg.data.length >= 20) {
            // The assembly code is more direct than the Solidity version using `abi.decode`.
            /// @solidity memory-safe-assembly
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            return super._msgSender();
        }
    }

    function _msgData() internal view virtual override returns (bytes calldata) {
        if (isTrustedForwarder(msg.sender) && msg.data.length >= 20) {
            return msg.data[:msg.data.length - 20];
        } else {
            return super._msgData();
        }
    }
}

/// @dev the ERC-165 identifier for this interface is `0x51945447`
interface IERC6551Executable {
    /**
     * @dev Executes a low-level operation if the caller is a valid signer on the account.
     *
     * Reverts and bubbles up error if operation fails.
     *
     * Accounts implementing this interface MUST accept the following operation parameter values:
     * - 0 = CALL
     * - 1 = DELEGATECALL
     * - 2 = CREATE
     * - 3 = CREATE2
     *
     * Accounts implementing this interface MAY support additional operations or restrict a signer's
     * ability to execute certain operations.
     *
     * @param to        The target address of the operation
     * @param value     The Ether value to be sent to the target
     * @param data      The encoded operation calldata
     * @param operation A value indicating the type of operation to perform
     * @return The result of the operation
     */
    function execute(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        payable
        returns (bytes memory);
}

library LibExecutor {
    uint8 constant OP_CALL = 0;
    uint8 constant OP_DELEGATECALL = 1;
    uint8 constant OP_CREATE = 2;
    uint8 constant OP_CREATE2 = 3;

    function _execute(address to, uint256 value, bytes calldata data, uint8 operation)
        internal
        returns (bytes memory)
    {
        if (operation == OP_CALL) return _call(to, value, data);
        if (operation == OP_DELEGATECALL) {
            address sandbox = LibSandbox.sandbox(address(this));
            if (sandbox.code.length == 0) LibSandbox.deploy(address(this));
            return _call(sandbox, value, abi.encodePacked(to, data));
        }
        if (operation == OP_CREATE) return abi.encodePacked(_create(value, data));
        if (operation == OP_CREATE2) {
            bytes32 salt = bytes32(data[:32]);
            bytes calldata bytecode = data[32:];
            return abi.encodePacked(_create2(value, salt, bytecode));
        }

        revert InvalidOperation();
    }

    function _call(address to, uint256 value, bytes memory data)
        internal
        returns (bytes memory result)
    {
        bool success;
        (success, result) = to.call{value: value}(data);

        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _create(uint256 value, bytes memory data) internal returns (address created) {
        bytes memory bytecode = data;

        assembly {
            created := create(value, add(bytecode, 0x20), mload(bytecode))
        }

        if (created == address(0)) revert ContractCreationFailed();
    }

    function _create2(uint256 value, bytes32 salt, bytes calldata data)
        internal
        returns (address created)
    {
        bytes memory bytecode = data;

        assembly {
            created := create2(value, add(bytecode, 0x20), mload(bytecode), salt)
        }

        if (created == address(0)) revert ContractCreationFailed();
    }
}

interface ISandboxExecutor {
    function extcall(address to, uint256 value, bytes calldata data)
        external
        returns (bytes memory result);

    function extcreate(uint256 value, bytes calldata data) external returns (address);

    function extcreate2(uint256 value, bytes32 salt, bytes calldata bytecode)
        external
        returns (address);

    function extsload(bytes32 slot) external view returns (bytes32 value);
}

/**
 * @title Sandbox Executor
 * @dev Allows the sandbox contract for an account to execute low-level operations
 */
abstract contract SandboxExecutor is ISandboxExecutor {
    /**
     * @dev Ensures that a given caller is the sandbox for this account
     */
    function _requireFromSandbox() internal view {
        if (msg.sender != LibSandbox.sandbox(address(this))) revert NotAuthorized();
    }

    /**
     * @dev Allows the sandbox contract to execute low-level calls from this account
     */
    function extcall(address to, uint256 value, bytes calldata data)
        external
        returns (bytes memory result)
    {
        _requireFromSandbox();
        return LibExecutor._call(to, value, data);
    }

    /**
     * @dev Allows the sandbox contract to create contracts on behalf of this account
     */
    function extcreate(uint256 value, bytes calldata bytecode) external returns (address) {
        _requireFromSandbox();

        return LibExecutor._create(value, bytecode);
    }

    /**
     * @dev Allows the sandbox contract to create deterministic contracts on behalf of this account
     */
    function extcreate2(uint256 value, bytes32 salt, bytes calldata bytecode)
        external
        returns (address)
    {
        _requireFromSandbox();
        return LibExecutor._create2(value, salt, bytecode);
    }

    /**
     * @dev Allows arbitrary storage reads on this account from external contracts
     */
    function extsload(bytes32 slot) external view returns (bytes32 value) {
        assembly {
            value := sload(slot)
        }
    }
}

/**
 * @title Base Executor
 * @dev Base configuration for all executors
 */
abstract contract BaseExecutor is Context, SandboxExecutor {
    function _beforeExecute() internal virtual {}

    function _isValidExecutor(address executor) internal view virtual returns (bool);
}

/**
 * @title ERC-6551 Executor
 * @dev Basic executor which implements the IERC6551Executable execution interface
 */
abstract contract ERC6551Executor is IERC6551Executable, ERC165, BaseExecutor {
    /**
     * Executes a low-level operation from this account if the caller is a valid executor
     *
     * @param to Account to operate on
     * @param value Value to send with operation
     * @param data Encoded calldata of operation
     * @param operation Operation type (0=CALL, 1=DELEGATECALL, 2=CREATE, 3=CREATE2)
     */
    function execute(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        payable
        virtual
        returns (bytes memory)
    {
        if (!_isValidExecutor(_msgSender())) revert NotAuthorized();

        _beforeExecute();

        return LibExecutor._execute(to, value, data, operation);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC6551Executable).interfaceId
            || super.supportsInterface(interfaceId);
    }
}

/**
 * @title Batch Executor
 * @dev Allows multiple operations to be executed from this account in a single transaction
 */
abstract contract BatchExecutor is BaseExecutor {
    struct Operation {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
    }

    /**
     * @notice Executes a batch of operations if the caller is authorized
     * @param operations Operations to execute
     */
    function executeBatch(Operation[] calldata operations)
        external
        payable
        returns (bytes[] memory)
    {
        if (!_isValidExecutor(_msgSender())) revert NotAuthorized();

        _beforeExecute();

        uint256 length = operations.length;
        bytes[] memory results = new bytes[](length);

        for (uint256 i = 0; i < length; i++) {
            results[i] = LibExecutor._execute(
                operations[i].to, operations[i].value, operations[i].data, operations[i].operation
            );
        }

        return results;
    }
}

/**
 * @title Account Lock
 * @dev Allows the root owner of a token bound account to lock access to an account until a
 * certain timestamp
 */
abstract contract Lockable {
    /**
     * @notice The timestamp at which this account will be unlocked
     */
    uint256 public lockedUntil;

    event LockUpdated(uint256 lockedUntil);

    /**
     * @dev Locks the account until a certain timestamp
     *
     * @param _lockedUntil The time at which this account will no longer be locke
     */
    function lock(uint256 _lockedUntil) external virtual {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        address _owner = _rootTokenOwner(chainId, tokenContract, tokenId);

        if (_owner == address(0)) revert NotAuthorized();
        if (msg.sender != _owner) revert NotAuthorized();

        if (_lockedUntil > block.timestamp + 365 days) {
            revert ExceedsMaxLockTime();
        }

        _beforeLock();

        lockedUntil = _lockedUntil;

        emit LockUpdated(_lockedUntil);
    }

    /**
     * @dev Returns the current lock status of the account as a boolean
     */
    function isLocked() public view virtual returns (bool) {
        return lockedUntil > block.timestamp;
    }

    function _rootTokenOwner(uint256 chainId, address tokenContract, uint256 tokenId)
        internal
        view
        virtual
        returns (address);

    function _beforeLock() internal virtual {}
}

/**
 * @title Nested Account Executor
 * @dev Allows the root owner of a nested token bound account to execute transactions directly
 * against the nested account, even if intermediate accounts have not been created.
 */
abstract contract NestedAccountExecutor is BaseExecutor {
    address immutable __self = address(this);
    address public immutable erc6551Registry;

    struct ERC6551AccountInfo {
        bytes32 salt;
        address tokenContract;
        uint256 tokenId;
    }

    constructor(address _erc6551Registry) {
        if (_erc6551Registry == address(0)) revert InvalidERC6551Registry();
        erc6551Registry = _erc6551Registry;
    }

    /**
     * Executes a low-level operation from this account if the caller is a valid signer on the
     * parent TBA specified in the proof
     *
     * @param to Account to operate on
     * @param value Value to send with operation
     * @param data Encoded calldata of operation
     * @param operation Operation type (0=CALL, 1=DELEGATECALL, 2=CREATE, 3=CREATE2)
     * @param proof An array of ERC-6551 account information specifying the ownership path from this
     * account to its parent
     */
    function executeNested(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        ERC6551AccountInfo[] calldata proof
    ) external payable returns (bytes memory) {
        uint256 length = proof.length;
        address current = _msgSender();

        ERC6551AccountInfo calldata accountInfo;
        for (uint256 i = 0; i < length; i++) {
            accountInfo = proof[i];
            address tokenContract = accountInfo.tokenContract;
            uint256 tokenId = accountInfo.tokenId;

            address next = ERC6551AccountLib.computeAddress(
                erc6551Registry, __self, accountInfo.salt, block.chainid, tokenContract, tokenId
            );

            if (tokenContract.code.length == 0) revert InvalidAccountProof();

            if (next.code.length > 0) {
                if (Lockable(next).isLocked()) revert AccountLocked();
            }

            try IERC721(tokenContract).ownerOf(tokenId) returns (address _owner) {
                if (_owner != current) revert InvalidAccountProof();
                current = next;
            } catch {
                revert InvalidAccountProof();
            }
        }

        if (!_isValidExecutor(current)) revert NotAuthorized();

        _beforeExecute();

        return LibExecutor._execute(to, value, data, operation);
    }
}

/**
 * @title Tokenbound Executor
 * @dev Enables basic ERC-6551 execution as well as batch, nested, and mult-account execution
 */
abstract contract TokenboundExecutor is
    ERC6551Executor,
    BatchExecutor,
    NestedAccountExecutor,
    ERC2771Context
{
    constructor(address multicallForwarder, address _erc6551Registry)
        ERC2771Context(multicallForwarder)
        NestedAccountExecutor(_erc6551Registry)
    {
        if (multicallForwarder == address(0)) revert InvalidMulticallForwarder();
    }

    function _msgSender()
        internal
        view
        virtual
        override(Context, ERC2771Context)
        returns (address sender)
    {
        return super._msgSender();
    }

    function _msgData()
        internal
        view
        virtual
        override(Context, ERC2771Context)
        returns (bytes calldata)
    {
        return super._msgData();
    }
}

// Source: https://github.com/ethereum-optimism/optimism/blob/96562692558e5c3851899488bcebe51fbe3b7f09/packages/contracts-bedrock/src/vendor/AddressAliasHelper.sol
library OPAddressAliasHelper {
    uint160 constant offset = uint160(0x1111000000000000000000000000000000001111);

    /// @notice Utility function that converts the address in the L1 that submitted a tx to
    /// the inbox to the msg.sender viewed in the L2
    /// @param l1Address the address in the L1 that triggered the tx to L2
    /// @return l2Address L2 address as viewed in msg.sender
    function applyL1ToL2Alias(address l1Address) internal pure returns (address l2Address) {
        unchecked {
            l2Address = address(uint160(l1Address) + offset);
        }
    }

    /// @notice Utility function that converts the msg.sender viewed in the L2 to the
    /// address in the L1 that submitted a tx to the inbox
    /// @param l2Address L2 address as viewed in msg.sender
    /// @return l1Address the address in the L1 that triggered the tx to L2
    function undoL1ToL2Alias(address l2Address) internal pure returns (address l1Address) {
        unchecked {
            l1Address = address(uint160(l2Address) - offset);
        }
    }
}

interface IAccountGuardian {
    function setTrustedImplementation(address implementation, bool trusted) external;

    function setTrustedExecutor(address executor, bool trusted) external;

    function defaultImplementation() external view returns (address);

    function isTrustedImplementation(address implementation) external view returns (bool);

    function isTrustedExecutor(address implementation) external view returns (bool);
}

/**
 * @title Modified Tokenbound ERC-6551 Account Implementation
 * @dev This contract is an implementation of Tokenbound's ERC-6551 Account standard with additional
 * functionality in the form of an owner-toggleable lock and removal of ERC4337 support
 */
contract AccountV3Modified is
    ERC721Holder,
    ERC1155Holder,
    LockableUnlockable,
    Overridable,
    Permissioned,
    ERC6551Account,
    TokenboundExecutor
{
    IAccountGuardian immutable guardian;

    /**
     * @param multicallForwarder The MulticallForwarder address
     * @param erc6551Registry The ERC-6551 Registry address
     * @param _guardian The AccountGuardian address
     */
    constructor(
        address multicallForwarder,
        address erc6551Registry,
        address _guardian
    ) TokenboundExecutor(multicallForwarder, erc6551Registry) {
        guardian = IAccountGuardian(_guardian);
    }

    /**
     * @notice Called whenever this account received Ether
     *
     * @dev Can be overriden via Overridable
     */
    receive() external payable override {
        _handleOverride();
    }

    /**
     * @notice Called whenever the calldata function selector does not match a defined function
     *
     * @dev Can be overriden via Overridable
     */
    fallback() external payable {
        _handleOverride();
    }

    /**
     * @notice Returns the owner of the token this account is bound to (if available)
     *
     * @dev Returns zero address if token is on a foreign chain or token contract does not exist
     *
     * @return address The address which owns the token this account is bound to
     */
    function owner() public view virtual returns (address) {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();
        return _tokenOwner(chainId, tokenContract, tokenId);
    }

    /**
     * @notice Returns whether a given ERC165 interface ID is supported
     *
     * @dev Can be overriden via Overridable except for base interfaces.
     *
     * @param interfaceId The interface ID to query for
     * @return bool True if the interface is supported, false otherwise
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC1155Receiver, ERC6551Account, ERC6551Executor)
        returns (bool)
    {
        bool interfaceSupported = super.supportsInterface(interfaceId);

        if (interfaceSupported) return true;

        _handleOverrideStatic();

        return false;
    }

    /**
     * @dev called whenever an ERC-721 token is received. Can be overriden via Overridable. Reverts
     * if token being received is the token the account is bound to.
     */
    function onERC721Received(address, address, uint256 tokenId, bytes memory)
        public
        virtual
        override
        returns (bytes4)
    {
        (uint256 chainId, address tokenContract, uint256 _tokenId) = ERC6551AccountLib.token();

        if (msg.sender == tokenContract && tokenId == _tokenId && chainId == block.chainid) {
            revert OwnershipCycle();
        }

        _handleOverride();

        return this.onERC721Received.selector;
    }

    /**
     * @dev called whenever an ERC-1155 token is received. Can be overriden via Overridable.
     */
    function onERC1155Received(address, address, uint256, uint256, bytes memory)
        public
        virtual
        override
        returns (bytes4)
    {
        _handleOverride();
        return this.onERC1155Received.selector;
    }

    /**
     * @dev called whenever a batch of ERC-1155 tokens are received. Can be overriden via Overridable.
     */
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public virtual override returns (bytes4) {
        _handleOverride();
        return this.onERC1155BatchReceived.selector;
    }

    /**
     * @notice Returns whether a given account is authorized to sign on behalf of this account
     *
     * @param signer The address to query authorization for
     * @return True if the signer is valid, false otherwise
     */
    function _isValidSigner(address signer, bytes memory)
        internal
        view
        virtual
        override
        returns (bool)
    {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();

        // Single level accuont owner is valid signer
        address _owner = _tokenOwner(chainId, tokenContract, tokenId);
        if (signer == _owner) return true;

        // Root owner of accuont tree is valid signer
        address _rootOwner = _rootTokenOwner(_owner, chainId, tokenContract, tokenId);
        if (signer == _rootOwner) return true;

        // Accounts granted permission by root owner are valid signers
        return hasPermission(signer, _rootOwner);
    }

    /**
     * Determines if a given hash and signature are valid for this account
     * @param hash Hash of signed data
     * @param signature ECDSA signature or encoded contract signature (v=0)
     */
    function _isValidSignature(bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        override(Signatory)
        returns (bool)
    {
        uint8 v = uint8(signature[64]);
        address signer;

        // Smart contract signature
        if (v == 0) {
            // Signer address encoded in r
            signer = address(uint160(uint256(bytes32(signature[:32]))));

            // Allow recursive signature verification
            if (!_isValidSigner(signer, "") && signer != address(this)) {
                return false;
            }

            // Signature offset encoded in s
            bytes calldata _signature = signature[uint256(bytes32(signature[32:64])):];

            return SignatureChecker.isValidERC1271SignatureNow(signer, hash, _signature);
        }

        ECDSA.RecoverError _error;
        (signer, _error) = ECDSA.tryRecover(hash, signature);

        if (_error != ECDSA.RecoverError.NoError) return false;

        return _isValidSigner(signer, "");
    }

    /**
     * @notice Returns whether a given account is authorized to execute transactions on behalf of
     * this account
     *
     * @param executor The address to query authorization for
     * @return True if the executor is authorized, false otherwise
     */
    function _isValidExecutor(address executor) internal view virtual override returns (bool) {
        (uint256 chainId, address tokenContract, uint256 tokenId) = ERC6551AccountLib.token();

        // Allow cross chain execution
        if (chainId != block.chainid) {
            // Allow execution from L1 account on OPStack chains
            if (OPAddressAliasHelper.undoL1ToL2Alias(_msgSender()) == address(this)) {
                return true;
            }

            // Allow execution from trusted cross chain bridges
            if (guardian.isTrustedExecutor(executor)) return true;
        }

        // Allow execution from owner
        address _owner = _tokenOwner(chainId, tokenContract, tokenId);
        if (executor == _owner) return true;

        // Allow execution from root owner of account tree
        address _rootOwner = _rootTokenOwner(_owner, chainId, tokenContract, tokenId);
        if (executor == _rootOwner) return true;

        // Allow execution from permissioned account
        if (hasPermission(executor, _rootOwner)) return true;

        return false;
    }

    /**
     * @dev Updates account state based on previous state and msg.data
     */
    function _updateState() internal virtual {
        _state = uint256(keccak256(abi.encode(_state, _msgData())));
    }

    /**
     * @dev Called before executing an operation. Reverts if account is locked. Ensures state is
     * updated prior to execution.
     */
    function _beforeExecute() internal virtual override {
        if (isLocked()) revert AccountLocked();
        _updateState();
    }

    /**
     * @dev Called before locking the account. Reverts if account is locked. Updates account state.
     */
    function _beforeLock() internal virtual override {
        if (isLocked()) revert AccountLocked();
        _updateState();
    }

    /**
     * @dev Called before unlocking the account. Reverts if account is locked. Updates account state.
     */
    function _beforeUnlock() internal virtual override {
        if (!isLocked()) revert AccountUnlocked();
        _updateState();
    }

    /**
     * @dev Called before setting overrides on the account. Reverts if account is locked. Updates
     * account state.
     */
    function _beforeSetOverrides() internal virtual override {
        if (isLocked()) revert AccountLocked();
        _updateState();
    }

    /**
     * @dev Called before setting permissions on the account. Reverts if account is locked. Updates
     * account state.
     */
    function _beforeSetPermissions() internal virtual override {
        if (isLocked()) revert AccountLocked();
        _updateState();
    }

    /**
     * @dev Returns the root owner of an account. If account is not owned by a TBA, returns the
     * owner of the NFT bound to this account. If account is owned by a TBA, iterates up token
     * ownership tree and returns root owner.
     *
     * *Security Warning*: the return value of this function can only be trusted if it is also the
     * address of the sender (as the code of the NFT contract cannot be trusted). This function
     * should therefore only be used for authorization and never authentication.
     */
    function _rootTokenOwner(uint256 chainId, address tokenContract, uint256 tokenId)
        internal
        view
        virtual
        override(Overridable, Permissioned, LockableUnlockable)
        returns (address)
    {
        address _owner = _tokenOwner(chainId, tokenContract, tokenId);

        return _rootTokenOwner(_owner, chainId, tokenContract, tokenId);
    }

    /**
     * @dev Returns the root owner of an account given a known account owner address (saves an
     * additional external call).
     */
    function _rootTokenOwner(
        address owner_,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId
    ) internal view virtual returns (address) {
        address _owner = owner_;

        while (ERC6551AccountLib.isERC6551Account(_owner, __self, erc6551Registry)) {
            (chainId, tokenContract, tokenId) = IERC6551Account(payable(_owner)).token();
            _owner = _tokenOwner(chainId, tokenContract, tokenId);
        }

        return _owner;
    }

    /**
     * @dev Returns the owner of the token which this account is bound to. Returns the zero address
     * if token does not exist on the current chain or if the token contract does not exist
     */
    function _tokenOwner(uint256 chainId, address tokenContract, uint256 tokenId)
        internal
        view
        virtual
        returns (address)
    {
        if (chainId != block.chainid) return address(0);
        if (tokenContract.code.length == 0) return address(0);

        try IERC721(tokenContract).ownerOf(tokenId) returns (address _owner) {
            return _owner;
        } catch {
            return address(0);
        }
    }
}

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

// OpenZeppelin Contracts (last updated v4.6.0) (proxy/Proxy.sol)

/**
 * @dev This abstract contract provides a fallback function that delegates all calls to another contract using the EVM
 * instruction `delegatecall`. We refer to the second contract as the _implementation_ behind the proxy, and it has to
 * be specified by overriding the virtual {_implementation} function.
 *
 * Additionally, delegation to the implementation can be triggered manually through the {_fallback} function, or to a
 * different contract through the {_delegate} function.
 *
 * The success and return data of the delegated call will be returned back to the caller of the proxy.
 */
abstract contract Proxy {
    /**
     * @dev Delegates the current call to `implementation`.
     *
     * This function does not return to its internal call site, it will return directly to the external caller.
     */
    function _delegate(address implementation) internal virtual {
        assembly {
            // Copy msg.data. We take full control of memory in this inline assembly
            // block because it will not return to Solidity code. We overwrite the
            // Solidity scratch pad at memory position 0.
            calldatacopy(0, 0, calldatasize())

            // Call the implementation.
            // out and outsize are 0 because we don't know the size yet.
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

            // Copy the returned data.
            returndatacopy(0, 0, returndatasize())

            switch result
            // delegatecall returns 0 on error.
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    /**
     * @dev This is a virtual function that should be overridden so it returns the address to which the fallback function
     * and {_fallback} should delegate.
     */
    function _implementation() internal view virtual returns (address);

    /**
     * @dev Delegates the current call to the address returned by `_implementation()`.
     *
     * This function does not return to its internal call site, it will return directly to the external caller.
     */
    function _fallback() internal virtual {
        _beforeFallback();
        _delegate(_implementation());
    }

    /**
     * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if no other
     * function in the contract matches the call data.
     */
    fallback() external payable virtual {
        _fallback();
    }

    /**
     * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if call data
     * is empty.
     */
    receive() external payable virtual {
        _fallback();
    }

    /**
     * @dev Hook that is called before falling back to the implementation. Can happen as part of a manual `_fallback`
     * call, or as part of the Solidity `fallback` or `receive` functions.
     *
     * If overridden should call `super._beforeFallback()`.
     */
    function _beforeFallback() internal virtual {}
}

contract AccountProxy is Proxy, ERC1967Upgrade {
    address immutable guardian;
    address immutable initialImplementation;

    constructor(address _guardian, address _initialImplementation) {
        if (_guardian == address(0) || _initialImplementation == address(0)) {
            revert InvalidImplementation();
        }
        guardian = _guardian;
        initialImplementation = _initialImplementation;
    }

    function initialize(address implementation) external {
        if (implementation != initialImplementation) {
            if (!IAccountGuardian(guardian).isTrustedImplementation(implementation)) {
                revert InvalidImplementation();
            }
        }
        if (ERC1967Upgrade._getImplementation() != address(0)) revert AlreadyInitialized();
        ERC1967Upgrade._upgradeTo(implementation);
    }

    function _implementation() internal view override returns (address) {
        return ERC1967Upgrade._getImplementation();
    }
}
