// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements comparing operations.

use super::bigint_core::{BigInt, Sign};
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
        // Rules out the exception,
        // for we internally allow `BigInt::from(0)` to be either positive or negative.
        if self.is_zero() && other.is_zero() {
            return true;
        }

        if self.sign == other.sign {
            eq_digits(self.as_digits(), other.as_digits())
        } else {
            false
        }
    }
}

impl Eq for BigInt {}

impl PartialOrd<Self> for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        // Rules out the exception,
        // for we internally allow `BigInt::from(0)` to be either positive or negative.
        if self.is_zero() && other.is_zero() {
            return Ordering::Equal;
        }

        match (&self.sign, &other.sign) {
            (Sign::Positive, Sign::Positive) => cmp_digits(self.as_digits(), other.as_digits()),
            (Sign::Positive, Sign::Negative) => Ordering::Greater,
            (Sign::Negative, Sign::Positive) => Ordering::Less,
            (Sign::Negative, Sign::Negative) => cmp_digits(other.as_digits(), self.as_digits()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::bigint_core::Sign;
    use crate::bigint::bigint_vec::{digits_be, digitvec_with_len};

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
    fn test_partial_eq_and_ord() {
        // (a, b, a == b, a >= b)
        let data = [
            (0, 0, true, true),
            (-1, 1, false, false),
            (1, -1, false, true),
            (1, 1, true, true),
            (-1, -1, true, true),
            (-1, 2, false, false),
            (1, 2, false, false),
            (2, 1, false, true),
        ];
        for (a, b, eq_result, ord_result) in data {
            let a = BigInt::from(a);
            let b = BigInt::from(b);
            assert_eq!(a == b, eq_result);
            assert_eq!(a >= b, ord_result);
        }
    }

    #[test]
    fn test_zero_partial_eq_and_ord() {
        let a = BigInt::new(digitvec_with_len(1), 1, Sign::Positive);
        let b = BigInt::new(digitvec_with_len(1), 1, Sign::Negative);
        assert_eq!(a == b, true);
        assert_eq!(a > b, false);
        assert_eq!(a < b, false);
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
