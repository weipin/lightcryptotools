// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::BigInt;
use crate::bigint::digit::Digit;

impl BigInt {
    pub(crate) fn is_even(&self) -> bool {
        assert!(!self.is_zero());

        let digit = self.digits_storage.first().unwrap();
        *digit & 1 == 0
    }

    pub(crate) fn is_odd(&self) -> bool {
        !self.is_even()
    }

    /// Returns the number of trailing zeros in the binary representation of `self`.
    /// Will panic if `self` is zero.
    pub(crate) fn trailing_zeros(&self) -> usize {
        assert!(!self.is_zero());

        if let Some(index) = self.as_digits().iter().position(|&x| x != 0) {
            index * Digit::BITS as usize + self.digits_storage[index].trailing_zeros() as usize
        } else {
            panic!("invalid binary representation")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_even_odd() {
        let data = [(1, false), (2, true), (3, false), (4, true), (17, false)];
        for (n, is_even) in data {
            assert_eq!(BigInt::from(n).is_even(), is_even);
            assert_eq!(BigInt::from(n).is_odd(), !is_even);
        }
    }

    #[test]
    fn test_trailing_zeros() {
        let shifting_bits_len_data = [
            0,
            1,
            2,
            Digit::BITS - 1,
            Digit::BITS,
            Digit::BITS + 1,
            Digit::BITS * 2 - 1,
            Digit::BITS * 2,
            Digit::BITS * 2 + 1,
        ];
        for i in shifting_bits_len_data {
            let a = BigInt::from(1) << i as usize;
            assert_eq!(a.trailing_zeros(), i as usize);
        }
    }
}
