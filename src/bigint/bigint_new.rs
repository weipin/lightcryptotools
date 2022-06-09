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
use crate::crypto::codecs::{hex_to_bytes, CodecsError};
use std::fmt;
use std::fmt::Display;

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
    /// `hex` must be 1-byte aligned -- having an even number of digits.
    /// `hex` is expected to have an optional sign prefix '+' or '-'.
    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<BigInt, ParseIntError> {
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
            return Err(ParseIntError::InvalidInput);
        }

        match hex_to_bytes(hex) {
            Ok(bytes) => Ok(Self::from_be_bytes(&bytes, sign)),
            Err(err) => Err(ParseIntError::CodecsError(err)),
        }
    }

    /// Creates a `BigInt` from integer representation in a given base.
    /// `s` is expected to have an optional sign prefix '+' or '-'.
    ///
    /// # Panic:
    ///
    /// This function panics if radix is not in the range from 2 to 36.
    pub fn from_str_radix<T: AsRef<[u8]>>(s: T, radix: u8) -> Result<BigInt, ParseIntError> {
        debug_assert!((2..=36).contains(&radix));

        let s = s.as_ref();
        if s.is_empty() {
            return Ok(BigInt::from(0));
        }

        let (sign, s) = match *s.first().unwrap() as char {
            '-' => (Sign::Negative, &s[1..]),
            '+' => (Sign::Positive, &s[1..]),
            _ => (Sign::Positive, s),
        };

        // "-" and "+" alone are both invalid hex input.
        if s.is_empty() {
            return Err(ParseIntError::InvalidInput);
        }

        let radix_bigint = BigInt::from(radix);
        let mut result = BigInt::zero();
        for &c in s {
            let n = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'z' => c - 87, // c - b'a' + 10
                b'A'..=b'Z' => c - 55, // c - b'A' + 10
                _ => return Err(ParseIntError::InvalidInput),
            };
            if n > radix {
                return Err(ParseIntError::InvalidInput);
            }

            result = result * &radix_bigint + BigInt::from(n);
        }

        result.sign = sign;
        Ok(result)
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

    pub fn zero() -> BigInt {
        Self::from(0)
    }

    pub fn one() -> BigInt {
        Self::from(1)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum ParseIntError {
    CodecsError(CodecsError),
    InvalidInput,
}

impl Display for ParseIntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseIntError::CodecsError(err) => write!(f, "Codecs error: {err}"),
            ParseIntError::InvalidInput => write!(f, "Invalid input"),
        }
    }
}

impl std::error::Error for ParseIntError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::bigint_new::ParseIntError;
    use crate::crypto::codecs::CodecsError;
    use crate::testing_tools::quickcheck::{BigIntHexString, HexString};
    use ::quickcheck_macros::quickcheck;

    #[test]
    fn test_from_hex() {
        let data = [
            ("", "00"),
            ("00", "00"),
            ("79be66", "79be66"),
            (
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
            ("-00", "00"),
            ("-79be66", "-79be66"),
            (
                "-79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "-79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
        ];
        for (a_hex, output) in data {
            let a = BigInt::from_hex(a_hex).unwrap();

            assert_eq!(a.to_lower_hex(), output);
        }
    }

    #[quickcheck]
    fn from_hex_and_to_hex_double_conversion(hex: BigIntHexString) -> bool {
        let n1 = BigInt::from_hex(hex.0).unwrap();
        let hex = n1.to_lower_hex();
        let n2 = BigInt::from_hex(hex).unwrap();
        n1 == n2
    }

    #[test]
    fn test_from_hex_with_errors() {
        let data = [
            ("0", ParseIntError::CodecsError(CodecsError::NotByteAligned)),
            (
                "79be661",
                ParseIntError::CodecsError(CodecsError::NotByteAligned),
            ),
            (
                "-0",
                ParseIntError::CodecsError(CodecsError::NotByteAligned),
            ),
            (
                "-0x79be66",
                ParseIntError::CodecsError(CodecsError::InvalidCharFound),
            ),
            ("-", ParseIntError::InvalidInput),
        ];
        for (a_hex, err) in data {
            assert_eq!(BigInt::from_hex(a_hex).unwrap_err(), err);
        }
    }

    #[test]
    fn test_from_str_radix_with_errors() {
        let data = [
            ("==791290", ParseIntError::InvalidInput),
            ("ab791290", ParseIntError::InvalidInput),
            ("-", ParseIntError::InvalidInput),
        ];
        for (a_str, err) in data {
            assert_eq!(BigInt::from_str_radix(a_str, 10).unwrap_err(), err);
        }
    }

    #[test]
    #[should_panic]
    fn from_str_radix_panic_on_invalid_radix_1() {
        let _ = BigInt::from_str_radix("123456", 1);
    }

    #[test]
    #[should_panic]
    fn from_str_radix_panic_on_invalid_radix_2() {
        let _ = BigInt::from_str_radix("123456", 37);
    }

    #[quickcheck]
    fn from_str_radix_16_eq_from_hex(hex: HexString) -> bool {
        let a = BigInt::from_hex(&hex.0).unwrap();
        let b = BigInt::from_str_radix(&hex.0, 16).unwrap();
        a == b
    }

    #[quickcheck]
    fn from_str_radix_double_conversion(hex: BigIntHexString) -> bool {
        // Tests against crate num_bigint
        let a = num_bigint::BigInt::parse_bytes(hex.0.as_bytes(), 16).unwrap();
        for radix in 2u8..=36 {
            let b = BigInt::from_str_radix(a.to_str_radix(radix as u32), radix).unwrap();
            if b != BigInt::from_hex(&hex.0).unwrap() {
                return false;
            }
        }
        true
    }
}
