// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements comparing operations.

use super::bigint_core::BigInt;
use super::bigint_slice::{is_valid_biguint_slice, BigUintSlice};
use std::cmp::Ordering;

/// Returns true if `a` and `b` are equal.
fn eq_digits(a: &BigUintSlice, b: &BigUintSlice) -> bool {
    debug_assert!(is_valid_biguint_slice(a));
    debug_assert!(is_valid_biguint_slice(b));

    a == b
}

/// Returns an Ordering between `a` and `b`.
pub(crate) fn cmp_digits(a: &BigUintSlice, b: &BigUintSlice) -> Ordering {
    debug_assert!(is_valid_biguint_slice(a));
    debug_assert!(is_valid_biguint_slice(b));

    let a_digits_len = a.len();
    let b_digits_len = b.len();
    match a_digits_len.cmp(&b_digits_len) {
        Ordering::Greater => Ordering::Greater,
        Ordering::Less => Ordering::Less,
        Ordering::Equal => a.iter().rev().cmp(b.iter().rev()),
    }
}

impl PartialEq<Self> for BigInt {
    fn eq(&self, other: &Self) -> bool {
        eq_digits(self.as_digits(), other.as_digits())
    }
}

impl Eq for BigInt {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::bigint_vec::digits_be;

    #[test]
    fn test_eq() {
        let a = digits_be!(3, 2, 1);
        let b = digits_be!(3, 2, 1);
        assert_eq!(&a, &b);
        assert_eq!(cmp_digits(&a, &b), Ordering::Equal);

        // least significant digits are zeros
        let a = digits_be!(3, 2, 1, 0);
        let b = digits_be!(3, 2, 1, 0);
        assert_eq!(&a, &b);
        assert_eq!(cmp_digits(&a, &b), Ordering::Equal);

        // zero
        let a = digits_be!(0);
        let b = digits_be!(0);
        assert_eq!(&a, &b);
        assert_eq!(cmp_digits(&a, &b), Ordering::Equal);
    }

    #[test]
    fn test_not_eq() {
        let a = digits_be!(0);
        let b = digits_be!(1);
        assert_ne!(&a, &b);

        let a = digits_be!(3, 7, 1);
        let b = digits_be!(3, 2, 1);
        assert_ne!(&a, &b);

        // least significant digits are zeros
        let a = digits_be!(3, 2, 1);
        let b = digits_be!(3, 2, 1, 0);
        assert_ne!(&a, &b);
    }

    #[test]
    #[should_panic]
    fn test_eq_digits_with_padding() {
        let a = digits_be!(0, 3, 2, 1);
        let b = digits_be!(3, 2, 1);
        assert_eq!(&a, &b);
    }

    #[test]
    fn test_less() {
        let a = digits_be!(3, 2, 1);
        let b = digits_be!(3, 2, 2);
        assert_eq!(cmp_digits(&a, &b), Ordering::Less);

        let a = digits_be!(3, 2, 1);
        let b = digits_be!(1, 3, 2, 1);
        assert_eq!(cmp_digits(&a, &b), Ordering::Less);

        let a = digits_be!(0);
        let b = digits_be!(1);
        assert_eq!(cmp_digits(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_greater() {
        let a = digits_be!(3, 2, 2);
        let b = digits_be!(3, 2, 1);
        assert_eq!(cmp_digits(&a, &b), Ordering::Greater);

        let a = digits_be!(1, 3, 2, 1);
        let b = digits_be!(3, 2, 1);
        assert_eq!(cmp_digits(&a, &b), Ordering::Greater);

        let a = digits_be!(1, 1);
        let b = digits_be!(1, 0);
        assert_eq!(cmp_digits(&a, &b), Ordering::Greater);

        let a = digits_be!(1);
        let b = digits_be!(0);
        assert_eq!(cmp_digits(&a, &b), Ordering::Greater);
    }

    #[test]
    #[should_panic]
    fn test_cmp_digits_with_padding() {
        let a = digits_be!(0, 3);
        let b = digits_be!(2);
        assert_eq!(cmp_digits(&a, &b), Ordering::Greater);
    }
}
