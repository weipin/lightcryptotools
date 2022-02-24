// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements multiplication operations.

use super::bigint_core::{BigInt, Sign};
use super::bigint_slice::{is_valid_biguint_slice, BigUintSlice};
use super::bigint_vec::{digitvec_with_len, DigitVec};
use super::cmp::cmp_digits;
use super::digit::{Digit, DoubleDigit, DIGIT_BITS};
use super::len::len_digits;
use super::zero::is_zero_digits;
use std::cmp::Ordering;
use std::ops::Mul;

/// Multiplies `a` with `b`, and fills the output to `result`,
/// returning the length of the output digits.
///
/// - `result` must have a length no less than the return value of [`multiplying_output_max_len`].
/// - `result` will be filled with 0 first, and then the output digits.
#[inline]
pub(crate) fn mul_digits(a: &BigUintSlice, b: &BigUintSlice, result: &mut [Digit]) -> usize {
    debug_assert!(is_valid_biguint_slice(a));
    debug_assert!(is_valid_biguint_slice(b));
    debug_assert!(result.len() >= multiplying_output_max_len(a.len(), b.len()));

    result.fill(0);

    // Outputs zero if `a = 0` or `b = 0`.
    if is_zero_digits(a) || is_zero_digits(b) {
        return 1;
    }

    // Employs the ["long multiplication"][1] algorithm:
    // multiplying each digit of the multiplier with the multiplicand,
    // and then add up all the properly shifted results.
    //
    // Also, the addition will be done concurrently with the multiplication,
    // storing the result to a properly shifted "output window".
    //
    // [1]: https://en.wikipedia.org/wiki/Multiplication_algorithm#Long_multiplication

    let (greater, smaller) = if cmp_digits(a, b) == Ordering::Less {
        (b, a)
    } else {
        (a, b)
    };

    // +1 for the possible carry at the most significant digit of `greater`.
    let output_window_len = greater.len() + 1;

    // For each digit `smaller_digit` from `smaller`,
    // multiplies it with each digit `greater_digit` from `greater`,
    // and "merges" the result to the properly shifted "output window".
    //
    // `output_window_offset` is in [0, smaller.len() - 1].
    for (output_window_offset, &smaller_digit) in smaller.iter().enumerate() {
        let mut carry: DoubleDigit = 0;

        let output_window =
            &mut result[output_window_offset..(output_window_offset + output_window_len)];
        for (&greater_digit, result_digit) in greater.iter().zip(output_window.iter_mut()) {
            // Calculates `t`:
            // t = smaller_digit * greater_digit + result_digit + carry
            //
            // - `t` can be represented by a double-digit type, for `t` < b^2:
            //      (b - 1) * (b - 1) + (b - 1) + (b - 1) = b^2 − 1 < b^2
            // - `result_digit` is an "in/out" digit from the "output window".
            //     - `result_digit` stores the accumulated value from the previous multiplying rounds.
            //     - The lower digit part of `t` will be stored back to `result_digit`.
            let t = (smaller_digit as DoubleDigit) * (greater_digit as DoubleDigit)
                + (*result_digit as DoubleDigit)
                + carry;

            // [Numeric casting][1] from a larger integer to a smaller integer will truncate.
            // https://doc.rust-lang.org/reference/expressions/operator-expr.html#numeric-cast
            *result_digit = t as Digit;
            carry = t >> DIGIT_BITS;
        }

        if carry > 0 {
            *output_window.last_mut().unwrap() = carry as Digit;
        }
    }

    len_digits(result)
}

impl<'a, 'b> Mul<&'b BigInt> for &'a BigInt {
    type Output = BigInt;

    fn mul(self, rhs: &BigInt) -> Self::Output {
        let a = self.as_digits();
        let b = rhs.as_digits();
        let mut output = digitvec_multiplying_output(a.len(), b.len());
        let output_len = mul_digits(a, b, &mut output);

        let sign = if self.sign == rhs.sign {
            Sign::Positive
        } else {
            Sign::Negative
        };
        BigInt::new(output, output_len, sign)
    }
}

impl<'a> Mul<&'a BigInt> for BigInt {
    type Output = BigInt;

    fn mul(self, rhs: &Self) -> Self::Output {
        (&self).mul(rhs)
    }
}

impl Mul for BigInt {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        (&self).mul(&rhs)
    }
}

/// Returns the length of the largest possible output of an multiplication operation: a * b.
///
/// `a_len` and `b_len` are the length of the operands.
#[inline]
fn multiplying_output_max_len(a_len: usize, b_len: usize) -> usize {
    a_len + b_len
}

/// Creates a `DigitVec` which can be used as output of an multiplication operation: a * b.
///
/// `a_len` and `b_len` are the length of the operands.
#[inline]
pub(crate) fn digitvec_multiplying_output(a_len: usize, b_len: usize) -> DigitVec {
    let max_len = multiplying_output_max_len(a_len, b_len);
    digitvec_with_len(max_len)
}

/// Same as [`digitvec_mul_output`],
/// except the resulting `DigitVec` will be filled with 1 instead of 0.
///
/// Can be used to test that the multiplication operations will first reset the output state.
#[cfg(test)]
#[inline]
fn digitvec_multiplying_output_filled_1(a_len: usize, b_len: usize) -> DigitVec {
    let mut vec = digitvec_multiplying_output(a_len, b_len);
    vec.fill(1);
    vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::bigint_vec::digits_be;
    use crate::bigint::digit::Digit;

    #[test]
    fn test_mul_digits() {
        // `data`: [(a, b, result)]
        let data = [
            // no carrying
            (
                digits_be!(1, 2, 3),
                digits_be!(4, 5, 6),
                digits_be!(4, 13, 28, 27, 18),
            ),
            // carrying without propagating
            (
                digits_be!(1, 2, 3),
                digits_be!(4, 5, Digit::MAX),
                digits_be!(4, 14, 23, 15, Digit::MAX - 2),
            ),
            // carrying with propagating
            (
                digits_be!(1, Digit::MAX, 3),
                digits_be!(4, 5, Digit::MAX),
                digits_be!(8, 8, 4, 18, Digit::MAX - 2),
            ),
            // carrying at the most significant digit
            (
                digits_be!(1, Digit::MAX, 3),
                digits_be!(Digit::MAX, 5, Digit::MAX),
                digits_be!(1, Digit::MAX - 2, 15, Digit::MAX - 10, 18, Digit::MAX - 2),
            ),
            // zero
            (digits_be!(1, 2, 3), digits_be!(0), digits_be!(0)),
            (digits_be!(0), digits_be!(1, 2, 3), digits_be!(0)),
            (digits_be!(0), digits_be!(0), digits_be!(0)),
        ];

        for (a, b, result) in data {
            let mut output = digitvec_multiplying_output_filled_1(a.len(), b.len());
            let output_len = mul_digits(&a, &b, &mut output);
            assert_eq!(result.len(), output_len);
            assert_eq!(result, output[..output_len]);
            assert_eq!(vec!(0; output.len() - output_len), output[output_len..]);
        }
    }

    #[test]
    fn test_signed_mul() {
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
            let c = BigInt::from(a * b);
            let a = BigInt::from(a);
            let b = BigInt::from(b);
            assert_eq!(a * b, c)
        }
    }
}
