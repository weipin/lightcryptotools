// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_slice::{is_valid_biguint_slice, BigUintSlice};
use crate::bigint::BigInt;

/// Returns true if `digits` represents a zero.
pub fn is_zero_digits(digits: &BigUintSlice) -> bool {
    debug_assert!(is_valid_biguint_slice(digits));

    digits.len() == 1 && *digits.first().unwrap() == 0
}

impl BigInt {
    pub fn is_zero(&self) -> bool {
        is_zero_digits(self.as_digits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::bigint_vec::digits_be;

    #[test]
    fn test_is_zero_digits() {
        let digits = digits_be!(0);
        assert!(is_zero_digits(&digits));

        let digits = digits_be!(6);
        assert!(!is_zero_digits(&digits));

        let digits = digits_be!(1, 0);
        assert!(!is_zero_digits(&digits));

        let digits = digits_be!(1, 2, 3);
        assert!(!is_zero_digits(&digits));
    }

    #[test]
    #[should_panic]
    fn test_is_zero_digits_with_padding() {
        let digits = digits_be!(0, 0);
        assert!(is_zero_digits(&digits));
    }
}
