// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements BigInt constructors

use super::bigint_core::{BigInt, Sign};
use super::bigint_vec::DigitVec;
use super::bytes::be_bytes_to_le_digits;
use crate::bigint::len::len_digits;
use crate::crypto::{hex_to_bytes, CodecsError};

impl BigInt {
    /// Creates and initializes a `BigInt`.
    ///
    /// This is the designated constructor that all other constructors should call.
    pub(crate) fn new(digits: DigitVec, digits_len: usize, sign: Sign) -> BigInt {
        BigInt {
            digits_storage: digits,
            digits_len,
            sign,
        }
    }

    /// Creates a `BigInt` from bytes in big-endian order.
    pub(crate) fn from_be_bytes(bytes: &[u8], sign: Sign) -> BigInt {
        let digits = be_bytes_to_le_digits(bytes);
        let digits_len = len_digits(&digits);

        Self::new(digits, digits_len, sign)
    }

    /// Creates a `BigInt` from hexadecimal representation `hex`.
    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<BigInt, CodecsError> {
        let hex = hex.as_ref();
        if hex.is_empty() {
            return Ok(BigInt::from(0));
        }

        let (sign, hex) = match *hex.first().unwrap() as char {
            '-' => (Sign::Negative, &hex[1..]),
            '+' => (Sign::Positive, &hex[1..]),
            _ => (Sign::Positive, hex),
        };

        // "-" and "+" alone are both invalid hex input.
        if hex.is_empty() {
            return Err(CodecsError::InvalidCharFound);
        }

        // Padding for byte alignment (e.g., 1 => 01).
        let bytes = if hex.len() & 1 == 0 {
            hex_to_bytes(hex)?
        } else {
            let mut t = Vec::with_capacity(hex.len() + 1);
            t.push(b'0');
            t.extend_from_slice(hex);
            hex_to_bytes(&t)?
        };

        Ok(Self::from_be_bytes(&bytes, sign))
    }

    /// Creates a `BigInt` from `u128`.
    pub(crate) fn from_u128(n: u128, sign: Sign) -> BigInt {
        let bytes = n.to_be_bytes();
        let digits = be_bytes_to_le_digits(&bytes);
        let digits_len = len_digits(&digits);

        Self::new(digits, digits_len, sign)
    }

    /// Creates a `BigInt` from `i128`.
    pub(crate) fn from_i128(i: i128) -> BigInt {
        if i >= 0 {
            Self::from_u128(i as u128, Sign::Positive)
        } else {
            // The absolute value of i128::MIN cannot be represented as an i128,
            // and attempting to calculate it will cause an overflow.
            let (negated, overflow) = i.overflowing_neg();
            let n = if overflow {
                // 1. Signed integers are represented by "two's complement",
                //     e.g., `i8::MIN` is represented by `0b10000000`.
                // 2. Rust's [numeric cast][1], `as`,
                //     is a no-op for casting between two integers of the same size (e.g., i8 -> u8).
                // 3. Combines 1 and 2, we can negate `i128::MIN` by `i128::MIN as u128`.
                //
                // [1]: https://doc.rust-lang.org/1.49.0/reference/expressions/operator-expr.html#semantics
                i as u128
            } else {
                negated as u128
            };
            Self::from_u128(n, Sign::Negative)
        }
    }

    pub(crate) fn zero() -> BigInt {
        Self::from(0)
    }

    pub(crate) fn one() -> BigInt {
        Self::from(1)
    }

    pub fn from_str_radix(s: &str, radix: u8) -> BigInt {
        debug_assert!((2..=32).contains(&radix));

        fn char_to_int(c: u8) -> u8 {
            match c {
                // 0 - 9
                48..=57 => c - 48,
                // 'a' - 'z'
                97..=122 => c - 87,
                // 'A' - 'Z'
                65..=90 => c - 55,
                _ => panic!("invalid char"),
            }
        }

        let radix_bigint = BigInt::from(radix);
        let mut result = BigInt::zero();
        for n in s.bytes().map(char_to_int) {
            if n > radix {
                panic!("digit greater than the specified radix")
            }

            result = result * &radix_bigint;
            result = result + BigInt::from(n);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing_tools::quickcheck::HexString;
    use ::quickcheck_macros::quickcheck;

    #[quickcheck]
    fn from_str_radix_16_eq_from_hex(hex: HexString) -> bool {
        let a = BigInt::from_hex(&hex.0).unwrap();
        let b = BigInt::from_str_radix(&hex.0, 16);
        a == b
    }
}
