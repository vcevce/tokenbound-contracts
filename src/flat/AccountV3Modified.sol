// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/SignatureChecker.sol)

// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/ECDSA.sol)

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
error AccountLocked();
error AccountUnlocked();
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
