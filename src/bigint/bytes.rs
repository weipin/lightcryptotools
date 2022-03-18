// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Converts digits to/from byte sequences.

use crate::bigint::digit::{Digit, DIGIT_BYTES};
use std::borrow::Cow;

/// Returns the memory representation of `digits` as a byte vector.
pub(crate) fn be_digits_to_be_bytes(digits: &[Digit]) -> Vec<u8> {
    if let Some((first, elements)) = digits.split_first() {
        let digits_len = digits.len();
        let mut bytes = Vec::with_capacity(digits_len * DIGIT_BYTES as usize);

        // Strips the leading zero bytes at the most significant digit.
        let leading_zero_bytes_len = first.leading_zeros() / 8;
        let first_bytes = first.to_be_bytes();
        bytes.extend_from_slice(&first_bytes[leading_zero_bytes_len as usize..]);

        for digit in elements {
            bytes.extend_from_slice(&digit.to_be_bytes());
        }
        bytes
    } else {
        Vec::new()
    }
}

/// Creates a digit vector from its byte array representation `bytes`.
/// The digits in the vector are in big-endian order.
pub(crate) fn be_bytes_to_be_digits(bytes: &[u8]) -> Vec<Digit> {
    if bytes.is_empty() {
        return Vec::new();
    }

    let extend_n = DIGIT_BYTES as usize - bytes.len() % DIGIT_BYTES as usize;
    let bytes: Cow<[u8]> = if extend_n > 0 {
        // Inserts padding for digit alignment.
        let mut bytes = bytes.to_vec();
        bytes.extend(vec![0; extend_n]);
        bytes.rotate_right(extend_n); // e.g., 123 => 0123
        Cow::Owned(bytes)
    } else {
        Cow::Borrowed(bytes)
    };

    let mut digits = Vec::with_capacity(bytes.len() / DIGIT_BYTES as usize);
    for chunk in bytes.chunks_exact(DIGIT_BYTES as usize) {
        let digit = Digit::from_be_bytes(chunk.try_into().unwrap());
        digits.push(digit);
    }

    digits
}

pub(crate) fn be_bytes_to_le_digits(bytes: &[u8]) -> Vec<Digit> {
    let mut digits = be_bytes_to_be_digits(bytes);
    digits.reverse();

    digits
}
