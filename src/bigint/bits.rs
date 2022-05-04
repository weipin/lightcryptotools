// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_core::BigInt;
use crate::bigint::bigint_slice::{is_valid_biguint_slice, BigUintSlice};
use crate::bigint::digit::Digit;
use crate::bigint::zero::is_zero_digits;

pub(crate) fn bit_len_digits(a: &BigUintSlice) -> usize {
    debug_assert!(is_valid_biguint_slice(a));

    if is_zero_digits(a) {
        return 0;
    }

    let most_significant_digit = a[a.len() - 1];
    a.len() * Digit::BITS as usize - most_significant_digit.leading_zeros() as usize
}

impl BigInt {
    /// Returns the number of bits representing the big integer.
    /// 0 is returned for the value zero.
    pub fn bit_len(&self) -> usize {
        bit_len_digits(self.as_digits())
    }

    pub(crate) fn le_bits(&self) -> Vec<bool> {
        if self.is_zero() {
            return vec![];
        }

        let digits = self.as_digits();
        let mut bits = Vec::with_capacity(self.bit_len());

        if let Some((last, elements)) = digits.split_last() {
            for digit in elements {
                let mut digit = *digit;
                for _ in 0..Digit::BITS {
                    bits.push(digit & 1 == 1);
                    digit >>= 1;
                }
            }

            // Handles the most significant digit
            let mut digit = *last;
            for _ in 0..(Digit::BITS - digit.leading_zeros()) {
                bits.push(digit & 1 == 1);
                digit >>= 1;
            }
        } else {
            panic!("invalid input")
        }

        debug_assert_eq!(bits.len(), self.bit_len());
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::digit::{Digit, DoubleDigit};

    #[test]
    fn test_bit_len() {
        let data = [
            (BigInt::from(0), 0),
            (BigInt::from(1), 1),
            (BigInt::from(Digit::MAX), Digit::BITS),
            (BigInt::from(Digit::MAX / 2), Digit::BITS - 1),
            (BigInt::from(Digit::MAX as DoubleDigit + 1), Digit::BITS + 1),
        ];

        for (a, bit_len) in data {
            assert_eq!(a.bit_len(), bit_len as usize);
        }
    }
}
