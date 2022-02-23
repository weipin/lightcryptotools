// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements addition operations.

use super::bigint_core::{BigInt, Sign};
use super::bigint_slice::{is_valid_biguint_slice, BigUintSlice};
use super::bigint_vec::{digitvec_with_len, DigitVec};
use super::cmp::cmp_digits;
use super::digit::Digit;
use super::helper_methods::carrying_add;
use std::cmp;
use std::ops::Add;

/// Adds `a` with `b`, and fills the output to `result`,
/// returning the length of the output digits.
///
/// - `result` must have a length no less than the return value of [`adding_output_max_len`].
/// - `result` will be filled with 0 first, and then the output digits.
#[inline]
pub(crate) fn add_digits(a: &BigUintSlice, b: &BigUintSlice, result: &mut [Digit]) -> usize {
    debug_assert!(is_valid_biguint_slice(a));
    debug_assert!(is_valid_biguint_slice(b));
    debug_assert!(result.len() >= adding_output_max_len(a.len(), b.len()));

    result.fill(0);

    // Employs the "long addition" algorithm:
    // adding digits from the least significant position to the most significant,
    // and propagating the resulting carry upwards.
    let (greater, smaller) = if cmp_digits(a, b) == cmp::Ordering::Less {
        (b, a)
    } else {
        (a, b)
    };
    let greater_digits_len = greater.len();
    let smaller_digits_len = smaller.len();

    let mut carry = false;
    let mut result_iter_mut = result.iter_mut();
    let mut result_digits_len = greater_digits_len;

    // Step 1:
    // For each digit `smaller_digit` from `smaller`,
    // and its aligned counterpart `greater_digit` from `greater`,
    // adds `greater_digit` with `smaller_digit`.
    for (&smaller_digit, &greater_digit) in smaller.iter().zip(greater.iter()) {
        let result = carrying_add(greater_digit, smaller_digit, carry);
        *result_iter_mut.next().unwrap() = result.0;
        carry = result.1;
    }

    // Step 2
    if carry {
        // Propagates the resulting carry from step 1,
        // going upwards through the rest of `greater`.
        for &digit in &greater[smaller_digits_len..] {
            let result = carrying_add(digit, 0, carry);
            *result_iter_mut.next().unwrap() = result.0;
            carry = result.1;
        }
        if carry {
            *result_iter_mut.next().unwrap() = 1;
            result_digits_len += 1
        }
    } else {
        // Copies the rest of `greater` to output.
        result[smaller_digits_len..greater_digits_len]
            .copy_from_slice(&greater[smaller_digits_len..]);
    }

    result_digits_len
}

impl<'a, 'b> Add<&'b BigInt> for &'a BigInt {
    type Output = BigInt;

    fn add(self, rhs: &BigInt) -> Self::Output {
        let a = self.as_digits();
        let b = rhs.as_digits();
        let mut output = digitvec_adding_output(a.len(), b.len());
        let output_len = add_digits(a, b, &mut output);

        BigInt::new(output, output_len, Sign::Positive)
    }
}

impl<'a> Add<&'a BigInt> for BigInt {
    type Output = BigInt;

    fn add(self, rhs: &Self) -> Self::Output {
        (&self).add(rhs)
    }
}

impl Add for BigInt {
    type Output = BigInt;

    fn add(self, rhs: Self) -> Self::Output {
        (&self).add(&rhs)
    }
}

/// Returns the length of the largest possible output of an addition operation: a + b.
///
/// `a_len` and `b_len` are the length of the operands.
#[inline]
fn adding_output_max_len(a_len: usize, b_len: usize) -> usize {
    cmp::max(a_len, b_len) + 1
}

/// Creates a `DigitVec` which can be used as output of an addition operation: a + b.
///
/// `a_len` and `b_len` are the length of the operands.
#[inline]
fn digitvec_adding_output(a_len: usize, b_len: usize) -> DigitVec {
    let max_len = adding_output_max_len(a_len, b_len);
    digitvec_with_len(max_len)
}

/// Same as [`digitvec_add_output`],
/// except the resulting `DigitVec` will be filled with 1 instead of 0.
///
/// Can be used to test that the addition operations will first reset the output state.
#[cfg(test)]
#[inline]
fn digitvec_adding_output_filled_1(a_len: usize, b_len: usize) -> DigitVec {
    let mut vec = digitvec_adding_output(a_len, b_len);
    vec.fill(1);
    vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::bigint_vec::digits_be;
    use crate::bigint::digit::Digit;

    #[test]
    fn test_add_digits() {
        // `data`: [(a, b, result)]
        let data = [
            // no carrying
            (
                digits_be!(1, 2, 3),
                digits_be!(4, 5, 6),
                digits_be!(5, 7, 9),
            ),
            // carrying without propagating
            (
                digits_be!(1, 2, 3),
                digits_be!(4, 5, Digit::MAX),
                digits_be!(5, 8, 2),
            ),
            // carrying with propagating
            (
                digits_be!(1, Digit::MAX, 3),
                digits_be!(4, 5, Digit::MAX),
                digits_be!(6, 5, 2),
            ),
            // carrying at the most significant digit
            (
                digits_be!(1, Digit::MAX, 3),
                digits_be!(Digit::MAX, 5, Digit::MAX),
                digits_be!(1, 1, 5, 2),
            ),
        ];

        for (a, b, result) in data {
            let mut output = digitvec_adding_output_filled_1(a.len(), b.len());
            let output_len = add_digits(&a, &b, &mut output);
            assert_eq!(result.len(), output_len);
            assert_eq!(result, output[..output_len]);
            assert_eq!(vec!(0; output.len() - output_len), output[output_len..]);
        }
    }
}
