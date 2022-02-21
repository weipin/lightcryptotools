// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Converts digits to/from byte sequences.

use crate::bigint::digit::{Digit, DIGIT_BYTES};

/// Returns the memory representation of `digits` as a byte vector,
/// each digit in big-endian order.
pub(crate) fn digits_to_bytes_be(digits: &[Digit]) -> Vec<u8> {
    let digits_len = digits.len();
    let mut bytes = Vec::with_capacity(digits_len * DIGIT_BYTES as usize);
    for digit in &digits[..digits_len] {
        bytes.extend_from_slice(&digit.to_be_bytes());
    }

    bytes
}

/// Creates a digit vector from its byte array representation `bytes`.
/// The representation of each digit is in big-endian order.
pub(crate) fn bytes_to_digits_be(bytes: &[u8]) -> Vec<Digit> {
    assert_eq!(bytes.len() % DIGIT_BYTES as usize, 0, "Not digit aligned");

    let mut digits = Vec::with_capacity(bytes.len() / DIGIT_BYTES as usize);
    for chunk in bytes.chunks_exact(DIGIT_BYTES as usize) {
        let digit = Digit::from_be_bytes(chunk.try_into().unwrap());
        digits.push(digit);
    }

    digits
}

/// Creates a digit vector from its byte array representation `bytes`.
/// The representation of each digit is in little-endian order.
pub(crate) fn bytes_to_digits_le(bytes: &[u8]) -> Vec<Digit> {
    assert_eq!(bytes.len() % DIGIT_BYTES as usize, 0, "Not digit aligned");

    let mut digits = Vec::with_capacity(bytes.len() / DIGIT_BYTES as usize);
    for chunk in bytes.chunks_exact(DIGIT_BYTES as usize) {
        let digit = Digit::from_le_bytes(chunk.try_into().unwrap());
        digits.push(digit);
    }

    digits
}

#[cfg(test)]
mod tests {
    #[cfg(not(u8_digit))]
    use super::*;

    #[cfg(not(u8_digit))]
    #[test]
    #[should_panic(expected = "Not digit aligned")]
    fn test_be_bytes_to_digits_not_digit_aligned() {
        let _ = bytes_to_digits_be(&[1, 2, 3]);
    }
}
