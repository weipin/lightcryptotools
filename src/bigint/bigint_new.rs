// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements BigInt constructors

use super::bigint_core::{BigInt, Sign};
use super::bigint_vec::DigitVec;
use super::bytes::{bytes_to_digits_be, bytes_to_digits_le};
use super::digit::DIGIT_BYTES;
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

    /// Creates a `BigInt` from hexadecimal representation `hex`.
    pub(crate) fn from_hex(hex: &str) -> Result<BigInt, CodecsError> {
        let mut bytes = hex_to_bytes(hex)?;
        // Inserts padding for the digit alignment required by `bytes_to_digits_be`.
        let n = bytes.len() % DIGIT_BYTES as usize;
        if n > 0 {
            let extend_n = DIGIT_BYTES as usize - n;
            bytes.extend(vec![0; extend_n]);
            bytes.rotate_right(extend_n); // e.g., 123 => 0123
        }
        let mut digits = bytes_to_digits_be(&bytes);

        // Reverses `digits`, for the hex representation is in big-endian order.
        digits.reverse();
        let digits_len = len_digits(&digits);

        Ok(Self::new(digits, digits_len, Sign::Positive))
    }

    /// Creates a `BigInt` from `u128`.
    pub(crate) fn from_u128(n: u128) -> BigInt {
        let bytes = n.to_le_bytes();
        let digits = bytes_to_digits_le(&bytes);
        let digits_len = len_digits(&digits);

        Self::new(digits, digits_len, Sign::Positive)
    }
}
