// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements digits length related functions.

use super::digit::Digit;

/// Returns the length of the digits stored in `digits`.
pub(crate) fn len_digits(digits: &[Digit]) -> usize {
    assert!(!digits.is_empty());

    // Searches for the first non-zero digit from the right,
    // for digits are stored in little-endian order.
    if let Some(index) = digits.iter().rposition(|&x| x != 0) {
        index + 1
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::bigint_vec::digits_be;

    #[test]
    fn test_len_digits() {
        // least significant digits are zeros
        let a = digits_be!(3, 2, 1, 0, 0);
        assert_eq!(len_digits(&a), 5);

        // most significant digits are zeros
        let a = digits_be!(0, 0, 0, 3, 2, 1, 0);
        assert_eq!(len_digits(&a), 4);

        // zeros
        let a = digits_be!(0, 0, 0);
        assert_eq!(len_digits(&a), 1);
    }

    #[test]
    #[should_panic]
    fn test_len_digits_with_empty_slice() {
        let a = digits_be!();
        assert_eq!(len_digits(&a), 0);
    }
}
