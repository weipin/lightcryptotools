// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements subtraction operations.

use super::add::{add_digits, digitvec_adding_output};
use super::bigint_core::BigInt;
use super::bigint_slice::{is_valid_biguint_slice, BigUintSlice};
use super::bigint_vec::{digitvec_with_len, DigitVec};
use super::cmp::cmp_digits;
use super::digit::Digit;
use super::helper_methods::borrowing_sub;
use super::len::len_digits;
use std::cmp;
use std::cmp::Ordering;
use std::ops::Sub;

/// Subtracts `b` from `a`, and fills the output to `result`,
/// returning the length of the output digits.
///
/// - `a` must be no less than `b` (a >= b).
/// - `result` must have a length no less than the return value of [`subtracting_output_max_len`].
/// - `result` will be filled with 0 first, and then the output digits.
///
/// # Panics:
///
/// Panics when `cmp_digits(a, b) == Ordering::Less`.
#[inline]
pub(crate) fn sub_digits(a: &BigUintSlice, b: &BigUintSlice, result: &mut [Digit]) -> usize {
    debug_assert!(is_valid_biguint_slice(a));
    debug_assert!(is_valid_biguint_slice(b));
    debug_assert!(result.len() >= subtracting_output_max_len(a.len(), b.len()));

    result.fill(0);

    let ordering = cmp_digits(a, b);
    if ordering == Ordering::Equal {
        return 1;
    } else if ordering == Ordering::Less {
        panic!("attempt to subtract with overflow");
    }

    // Employs the "long subtraction" algorithm:
    // subtracting digits from the least significant position to the most significant,
    // and propagating the resulting borrow upwards.
    let greater = a;
    let smaller = b;
    let greater_digits_len = len_digits(greater);
    let smaller_digits_len = len_digits(smaller);

    let mut borrow = false;
    let mut result_iter_mut = result.iter_mut();

    // Step 1:
    // For each digit `smaller_digit` from `smaller`,
    // and its aligned counterpart `greater_digit` from `greater`,
    // subtracts `smaller_digit` from `greater_digit`.
    for (&smaller_digit, &greater_digit) in smaller.iter().zip(greater.iter()) {
        (*result_iter_mut.next().unwrap(), borrow) =
            borrowing_sub(greater_digit, smaller_digit, borrow);
    }

    // Step 2
    if borrow {
        // Propagates the resulting borrow from step 1,
        // going upwards through the rest of `greater`.
        for &digit in &greater[smaller_digits_len..] {
            (*result_iter_mut.next().unwrap(), borrow) = borrowing_sub(digit, 0, borrow);
        }
    } else {
        // Copies the rest of `greater` to output.
        result[smaller_digits_len..greater_digits_len]
            .copy_from_slice(&greater[smaller_digits_len..]);
    }

    len_digits(result)
}

impl<'a, 'b> Sub<&'b BigInt> for &'a BigInt {
    type Output = BigInt;

    fn sub(self, rhs: &BigInt) -> Self::Output {
        let a = self.as_digits();
        let b = rhs.as_digits();

        if self.sign != rhs.sign {
            let mut output = digitvec_adding_output(a.len(), b.len());
            let output_len = add_digits(a, b, &mut output);
            BigInt::new(output, output_len, self.sign)
        } else {
            match cmp_digits(a, b) {
                Ordering::Less => {
                    let mut output = digitvec_subtracting_output(b.len(), a.len());
                    let output_len = sub_digits(b, a, &mut output);
                    let sign = -(&self.sign);
                    BigInt::new(output, output_len, sign)
                }
                Ordering::Equal => BigInt::from(0),
                Ordering::Greater => {
                    let mut output = digitvec_subtracting_output(a.len(), b.len());
                    let output_len = sub_digits(a, b, &mut output);
                    BigInt::new(output, output_len, self.sign)
                }
            }
        }
    }
}

impl<'a> Sub<&'a BigInt> for BigInt {
    type Output = BigInt;

    fn sub(self, rhs: &Self) -> Self::Output {
        (&self).sub(rhs)
    }
}

impl<'a> Sub<BigInt> for &'a BigInt {
    type Output = BigInt;

    fn sub(self, rhs: BigInt) -> Self::Output {
        (self).sub(&rhs)
    }
}

impl Sub for BigInt {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        (&self).sub(&rhs)
    }
}

/// Returns the length of the largest possible output of an subtraction operation: a - b.
///
/// `a_len` and `b_len` are the length of the operands.
#[inline]
fn subtracting_output_max_len(a_len: usize, b_len: usize) -> usize {
    cmp::max(a_len, b_len)
}

/// Creates a `DigitVec` which can be used as output of an subtraction operation: a - b.
///
/// `a_len` and `b_len` are the length of the operands.
#[inline]
pub(crate) fn digitvec_subtracting_output(a_len: usize, b_len: usize) -> DigitVec {
    let max_len = subtracting_output_max_len(a_len, b_len);
    digitvec_with_len(max_len)
}

/// Same as [`digitvec_sub_output`],
/// except the resulting `DigitVec` will be filled with 1 instead of 0.
///
/// Can be used to test that the subtraction operations will first reset the output state.
#[cfg(test)]
#[inline]
fn digitvec_subtracting_output_filled_1(a_len: usize, b_len: usize) -> DigitVec {
    let mut vec = digitvec_subtracting_output(a_len, b_len);
    vec.fill(1);
    vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::bigint_vec::digits_be;
    use crate::bigint::digit::Digit;

    #[test]
    fn test_sub_digits() {
        // `data`: [(a, b, result)]
        let data = [
            // no borrow
            (digits_be!(20, 10), digits_be!(2, 1), digits_be!(18, 9)),
            // borrow without propagating
            (
                digits_be!(5, 3),
                digits_be!(2, Digit::MAX),
                digits_be!(2, 4),
            ),
            // borrow with propagating,
            (
                digits_be!(1, 0, 0, 0, 3),
                digits_be!(Digit::MAX),
                digits_be!(Digit::MAX, Digit::MAX, Digit::MAX, 4),
            ),
            // zero
            (digits_be!(1, 1), digits_be!(1, 1), digits_be!(0)),
            (digits_be!(0), digits_be!(0), digits_be!(0)),
        ];

        for (a, b, result) in data {
            let mut output = digitvec_subtracting_output_filled_1(a.len(), b.len());
            let output_len = sub_digits(&a, &b, &mut output);
            assert_eq!(result.len(), output_len);
            assert_eq!(result, output[..output_len]);
            assert_eq!(vec!(0; output.len() - output_len), output[output_len..]);
        }
    }

    #[test]
    #[should_panic]
    fn test_sub_digits_with_overflow() {
        let a = digits_be!(1, 2, 3);
        let b = digits_be!(1, 2, 4);
        let mut output = digitvec_subtracting_output(a.len(), b.len());
        sub_digits(&a, &b, &mut output);
    }

    #[test]
    fn test_signed_sub() {
        let data = [
            (0, 0),
            (2, 1),
            (1, 2),
            (1, 1),
            (-2, -1),
            (-1, -2),
            (-1, -1),
            (2, -1),
            (-2, 1),
            (1, -2),
            (-1, 2),
            (1, -1),
            (-1, 1),
        ];
        for (a, b) in data {
            let c = BigInt::from(a - b);
            let a = BigInt::from(a);
            let b = BigInt::from(b);
            assert_eq!(a - b, c)
        }
    }
}
