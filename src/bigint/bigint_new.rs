// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements BigInt constructors

use super::bigint_core::{BigInt, Sign};
use super::bigint_vec::DigitVec;
use super::bytes::bytes_to_digits_be;
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

    /// Creates a `BigInt` from hexadecimal representation `hex`.
    pub fn from_hex(hex: &str) -> Result<BigInt, CodecsError> {
        let bytes = hex_to_bytes(hex)?;
        let mut digits = bytes_to_digits_be(&bytes);

        // Reverses `digits`, for the hex representation is in big-endian order.
        digits.reverse();

        let digits_len = digits.len();
        Ok(Self::new(digits, digits_len, Sign::Positive))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_hex() {
        let hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let a = BigInt::from_hex(hex).unwrap();
        assert_eq!(format!("{a}"), format!("0x{hex}"));
    }
}
