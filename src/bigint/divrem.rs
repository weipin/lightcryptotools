// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements division operations.

use super::bigint_core::{BigInt, Sign};
use super::bigint_slice::{is_valid_biguint_slice, BigUintSlice};
use super::bigint_vec::{digitvec_with_len, DigitVec};
use super::cmp::cmp_digits;
use super::digit::{Digit, DoubleDigit, DIGIT_BITS};
use super::len::len_digits;
use super::zero::is_zero_digits;
use crate::bigint::helper_methods::{borrowing_sub, carrying_add};
use std::cmp::Ordering;
use std::ops::{Div, Rem};

/// Divides `dividend` by `divisor`, and fills the outputs to `quotient` and `remainder`.
///
/// Returns the length of the quotient digits, and the length of the remainder digits.
///
/// - `quotient` must have a length no less than the return value of [`div_rem_quotient_max_len`].
/// - `remainder` must have a length no less than the return value of [`div_rem_remainder_max_len`].
/// - `quotient` and `remainder` will be filled with 0 first, and then the output digits.
/// - Will panic if `divisor` represents 0.
#[inline]
fn div_rem_digits(
    dividend: &BigUintSlice,
    divisor: &BigUintSlice,
    quotient: &mut [Digit],
    remainder: &mut [Digit],
) -> (usize, usize) {
    debug_assert!(is_valid_biguint_slice(dividend));
    debug_assert!(is_valid_biguint_slice(divisor));
    debug_assert!(quotient.len() >= div_rem_quotient_max_len(dividend.len()));
    debug_assert!(remainder.len() >= div_rem_remainder_max_len(divisor.len()));

    quotient.fill(0);
    remainder.fill(0);

    assert!(!is_zero_digits(divisor), "attempt to divide by zero");

    // For `dividend = 0`, `quotient = remainder = 0`.
    if is_zero_digits(dividend) {
        return (1, 1);
    }

    let dividend_digits_len = dividend.len();
    let divisor_digits_len = divisor.len();
    let ordering = cmp_digits(dividend, divisor);
    if ordering == Ordering::Equal {
        // For `dividend = divisor`,
        // `quotient = 1` and `remainder = 0`.
        quotient[0] = 1;
        return (1, 1);
    } else if ordering == Ordering::Less {
        // For `dividend < divisor`,
        // `quotient = 0` and `remainder = dividend`.
        remainder[..dividend_digits_len].copy_from_slice(dividend);
        return (1, dividend_digits_len);
    }

    // For divisor with only one digit `divisor0`,
    // divides each digit from `dividend` by `divisor0`.
    if divisor_digits_len == 1 {
        let divisor0 = *divisor.first().unwrap() as DoubleDigit;
        let mut remainder0: DoubleDigit = 0;

        // Divides from the most significant digit to the least significant.
        // The iterators’ direction are reversed for the digits are stored in little-endian order.
        for (dividend_digit, quotient_digit) in
            dividend.iter().rev().zip(quotient.iter_mut().rev())
        {
            let t = remainder0 << DIGIT_BITS | *dividend_digit as DoubleDigit;
            *quotient_digit = (t / divisor0) as Digit;
            remainder0 = t % divisor0
        }

        remainder[0] = remainder0 as Digit;
        return (len_digits(quotient), 1);
    }

    // Employs Knuth's Algorithm D from the book "The Art of Computer Programming, Volume 2".
    // The algorithm can be found in section 4.3.1 with improvements from its exercises.
    //
    // Algorithm D is similar to long division but eliminates the guesswork part.
    // It requires one zero padding at the most significant digit of the dividend to work,
    // e.g., 1234 is padded as 01234.
    //
    // To demonstrate the algorithm, a step by step work through of 3142/53 is provided below.
    // - To help realize the situation, the base number is 10 (b = 10).
    // - The normalizing step is omitted.
    //
    // | #step | digits storage  | dividend window | q   | remain | accumulated quotient  |
    // |-------|-----------------|-----------------|-----|--------|-----------------------|
    // | 1     | 03142           | 031/53          | 0   | 31     | 0                     |
    // |       | ⌞⎽⌟             |                 |     |        |                       |
    // |       |                 |                 |     |        |                       |
    // | 2     | 03142           | 314/53          | 5   | 49     | 05                    |
    // |       |  ⌞⎽⌟            |                 |     |        |                       |
    // |       |                 |                 |     |        |                       |
    // | 3     | 00492           | 492/53          | 9   | 15*    | 059*                  |
    // |       |   ⌞⎽⌟           |                 |     |        |                       |
    //
    // *: final result

    let divisor0 = divisor[divisor_digits_len - 1]; // the most significant digit of the divisor

    // For variables representing the digits of a big integer,
    // tailing '0' is used to refer to the most significant digit,
    // '1' for the second most significant digit, and so on.
    //
    // Take `foo = 8634` for an example:
    // `foo0 = 8`
    // `foo1 = 6`
    // `foo2 = 3`
    // `foo4 = 4`
    let divisor1 = divisor[divisor_digits_len - 2];

    // Normalizes the divisor.
    //
    // Left shifts the divisor until its most significant digit is no less than `b/2`.
    // Only the most significant two digits of divisor (after normalizing) will be used:
    // `divisor0_normalized` and `divisor1_normalized`.
    //
    // `d`: the scaling factor from the Algorithm D.
    // `next_d`: `next_d = DIGIT_BITS - d`, will be repeatedly used.
    let (divisor0_normalized, divisor1_normalized, d, next_d) = {
        // Determines `d`, to meet the condition `divisor0_normalized >= b/2` (Theorem B).
        //
        // Equivalent code:
        // ```
        // let DIGIT_MAX_HALF = 1 << (DIGIT_BITS - 1);
        // let mut d = 0;
        // while divisor0 < DIGIT_MAX_HALF {
        //    d += 1;
        //    divisor0 <<= 1;
        // }
        // ```
        let d = divisor0.leading_zeros() as Digit; // Adapted from the crate num-bigint

        let next_d = DIGIT_BITS as Digit - d;
        let divisor0_normalized;
        let divisor1_normalized;
        if d > 0 {
            // Performs left shift on `divisor`
            divisor0_normalized = (divisor0 << d) | (divisor1 >> next_d);
            if divisor_digits_len > 2 {
                let divisor2 = divisor[divisor_digits_len - 3];
                divisor1_normalized = (divisor1 << d) | (divisor2 >> next_d);
            } else {
                divisor1_normalized = divisor1 << d;
            }
        } else {
            divisor0_normalized = divisor0;
            divisor1_normalized = divisor1;
        }

        (
            divisor0_normalized as DoubleDigit,
            divisor1_normalized as DoubleDigit,
            d,
            next_d,
        )
    };

    // Makes a mutable copy of the dividend.
    // - Length +1 for the zero padding required by the algorithm at the most significant digit,
    //     e.g., 123 becomes 0123.
    // - Length +1 for another padding reserved to check the rare case that ``q_hat - 3 = q``.
    //     The check is done by temporarily setting value 1 at the most significant digit,
    //     e.g., 0123 becomes 10123, and detecting subtraction overflow without panicking.
    let mut dividend_digits_storage = vec![0; dividend_digits_len + 2];
    dividend_digits_storage[..dividend_digits_len].copy_from_slice(dividend);

    // "window" length, +2 for the same reason above.
    let dividend_window_len = divisor_digits_len + 2;

    // The number of steps to perform.
    // Each step produces a quotient digit.
    let quotient_num_len = dividend_digits_len - divisor_digits_len + 1;

    // The quotient is calculated from the most significant position to the least significant.
    // Reverses the iterator for the digits are stored in little-endian order.
    let mut quotient_iter = quotient[..quotient_num_len].iter_mut().rev();

    // Performs the steps.
    // Shifts the window for each step, starting at the end of the `dividend_digits_storage`.
    rwindows_mut_each(
        &mut dividend_digits_storage,
        dividend_window_len,
        |dividend_window| {
            let mut dividend_window_iter = dividend_window.iter().rev();
            dividend_window_iter.next(); // skips the digit for the borrow checking

            let dividend0 = *dividend_window_iter.next().unwrap();
            let dividend1 = *dividend_window_iter.next().unwrap();
            let dividend2 = *dividend_window_iter.next().unwrap();

            // Scales the dividend window with `d`.
            let (dividend0_normalized, dividend1_normalized, dividend2_normalized) = if d == 0 {
                (
                    dividend0 as DoubleDigit,
                    dividend1 as DoubleDigit,
                    dividend2 as DoubleDigit,
                )
            } else {
                let dividend0_normalized = dividend0 << d | dividend1 >> next_d;
                let dividend1_normalized = dividend1 << d | dividend2 >> next_d;
                let dividend2_normalized = if let Some(dividend3) = dividend_window_iter.next()
                {
                    dividend2 << d | dividend3 >> next_d
                } else {
                    dividend2 << d
                };

                (
                    dividend0_normalized as DoubleDigit,
                    dividend1_normalized as DoubleDigit,
                    dividend2_normalized as DoubleDigit,
                )
            };

            // Calculates `q_hat` and `r_hat`.
            //
            // * `q_hat`:
            //   1. From the algorithm D:
            //       ```
            //       q_hat = std::cmp::min(
            //           (dividend0_normalized * b + dividend1_normalized) / divisor0_normalized,
            //           Digit::MAX,
            //       );
            //       ```
            //  2. Distinguishes the cases by evaluating a branch condition:
            //      `dividend0_normalized == divisor0_normalized`.
            //
            //
            // * `q_hat_found`: to ignore the `q_hat > q` test.
            //
            //
            // Knuth's Algorithm D uses [the hat operator][1], a mathematical notation,
            // to represent the estimated values.
            // Hence the postfix "_hat" in the corresponding variable names.
            //
            // [1]: https://en.wikipedia.org/wiki/Hat_operator
            let (mut q_hat, r_hat, q_hat_found) = if dividend0_normalized == divisor0_normalized
            {
                // For `dividend0_normalized == divisor0_normalized`, `q_hat >= (b - 1)`.
                let q_hat = Digit::MAX as DoubleDigit; // min(q_hat, Digit::MAX)

                // `r_hat = dividend1_normalized + divisor0_normalized`,
                // for `dividend0_normalized == divisor0_normalized`.
                // ```
                // r_hat = dividend0_normalized * b + dividend1_normalized - q_hat * divisor0_normalized
                // = dividend0_normalized * b + dividend1_normalized - (b - 1) * divisor0_normalized
                // = (dividend0_normalized - divisor0_normalized) * b + dividend1_normalized + divisor0_normalized
                // = dividend1_normalized + divisor0_normalized
                // ```
                let r_hat = dividend1_normalized + divisor0_normalized;

                // For `dividend0_normalized == divisor0_normalized`,
                // it's possible that `r_hat > b` (rare).
                // If this case happens, ignores the `q_hat > q` test.
                //
                // 1. The test will always fail, for `(r_hat * b + dividend2_normalized) > b^2`.
                // 2. The calculation above will overflow the `DoubleDigit`.
                // 3. Combines 1 and 2, sets `q_hat_found = true` for `r_hat > b`.
                if r_hat <= Digit::MAX as DoubleDigit {
                    (q_hat, Some(r_hat), false)
                } else {
                    (q_hat, None, true)
                }
            } else {
                // - For `dividend0_normalized < divisor0_normalized`, `q_hat < (b - 1)`.
                // - For `dividend0_normalized > divisor0_normalized`, the condition is invalid
                //   due to `dividend_window / divisor < b` from the algorithm D.
                let t = (dividend0_normalized << DIGIT_BITS) | dividend1_normalized;
                let q_hat = t / divisor0_normalized;
                let r_hat = t % divisor0_normalized;

                (q_hat, Some(r_hat), false)
            };

            if !q_hat_found {
                let r_hat = r_hat.unwrap();

                // Tests `q_hat > q` by
                // `q_hat * divisor1_normalized > (r_hat * b + dividend2_normalized)`
                let mut lhs = q_hat * divisor1_normalized;

                debug_assert!(r_hat <= Digit::MAX as DoubleDigit); // to ensure `r_hat << DIGIT_BITS` won't overflow
                let mut rhs = (r_hat << DIGIT_BITS) + dividend2_normalized;

                if lhs > rhs {
                    q_hat -= 1;

                    // Tests `q_hat > q` the second time.
                    //
                    // For `q_hat -= 1`,
                    // `lhs` becomes `lhs - divisor1_normalized`, and
                    // `rhs` becomes `rhs + divisor0_normalized * b`.
                    //
                    // 1. `rhs > b^2` for `(r_hat + divisor0_normalized) >= b`:
                    // ```
                    // rhs = rhs + divisor0_normalized * b
                    // = r_hat * b + dividend2_normalized + divisor0_normalized * b
                    // = (r_hat + divisor0_normalized) * b + dividend2_normalized
                    // > b^2
                    // ```
                    //
                    // 2. We already know that `lhs < b^2`.
                    //
                    // 3. Combines 1 and 2, for `(r_hat + divisor0_normalized) >= b`,
                    // `lhs > rhs` is false (that is `q_hat = q`).
                    //
                    // 4. For 1, the calculation of `rhs` will overflow the `DoubleDigit`.
                    //
                    // 5. Combines 3 and 4, the `q_hat > q` test is only performed when
                    // `(r_hat + divisor0_normalized) < b`.
                    if (r_hat + divisor0_normalized) <= Digit::MAX as DoubleDigit {
                        lhs -= divisor1_normalized;
                        rhs += divisor0_normalized << DIGIT_BITS;
                        if lhs > rhs {
                            q_hat -= 1;
                        }
                    }
                }
            }

            let mut q_hat = q_hat as Digit;

            // Adds the temporary borrow padding,
            // for the rare case that ``q_hat - 1 = q`` at this point.
            *dividend_window.last_mut().unwrap() = 1;

            // `dividend_window -= divisor * q_hat`
            sub_mul_digits(&mut *dividend_window, divisor, q_hat);

            if *dividend_window.last_mut().unwrap() == 0 {
                // `q_hat - 1 = q`, for the borrowing is triggered.
                q_hat -= 1;
                // `dividend_window -= divisor`,
                assign_add_digits(dividend_window, divisor);
            }
            // Removes the borrow padding.
            *dividend_window.last_mut().unwrap() = 0;

            // Accumulates `quotient`.
            *quotient_iter.next().unwrap() = q_hat;
        },
    );

    // The digits left in the dividend storage is `remainder`.
    remainder.copy_from_slice(&dividend_digits_storage[0..remainder.len()]);

    (len_digits(quotient), len_digits(remainder))
}

impl<'a, 'b> Div<&'b BigInt> for &'a BigInt {
    type Output = BigInt;

    fn div(self, rhs: &BigInt) -> Self::Output {
        let a = self.as_digits();
        let b = rhs.as_digits();
        let mut quotient = digitvec_div_rem_quotient(a.len());
        let mut remainder = digitvec_div_rem_remainder(b.len());
        let (quotient_len, _) = div_rem_digits(a, b, &mut quotient, &mut remainder);

        BigInt::new(quotient, quotient_len, Sign::Positive)
    }
}

impl<'a> Div<&'a BigInt> for BigInt {
    type Output = BigInt;

    fn div(self, rhs: &Self) -> Self::Output {
        (&self).div(rhs)
    }
}

impl Div for BigInt {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        (&self).div(&rhs)
    }
}

impl<'a, 'b> Rem<&'b BigInt> for &'a BigInt {
    type Output = BigInt;

    fn rem(self, rhs: &BigInt) -> Self::Output {
        let a = self.as_digits();
        let b = rhs.as_digits();
        let mut quotient = digitvec_div_rem_quotient(a.len());
        let mut remainder = digitvec_div_rem_remainder(b.len());
        let (_, remainder_len) = div_rem_digits(a, b, &mut quotient, &mut remainder);

        BigInt::new(remainder, remainder_len, Sign::Positive)
    }
}

impl<'a> Rem<&'a BigInt> for BigInt {
    type Output = BigInt;

    fn rem(self, rhs: &Self) -> Self::Output {
        (&self).rem(rhs)
    }
}

impl Rem for BigInt {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        (&self).rem(&rhs)
    }
}

/// Iterates `slice` over all contiguous windows of length `window_size`,
/// and calls a closure `f` on each window, starting at the end of the slice.
///
/// - The windows overlap.
/// - Will panic if `slice` is shorter than `size`.
fn rwindows_mut_each<T>(slice: &mut [T], window_size: usize, mut f: impl FnMut(&mut [T])) {
    assert!(
        window_size <= slice.len(),
        "the window is larger than the slice"
    );

    let mut start = slice.len() - window_size;
    let mut end = start + window_size;
    loop {
        f(&mut slice[start..end]);
        if start == 0 {
            break;
        }
        start -= 1;
        end -= 1;
    }
}

/// a -= b * c
#[inline]
fn sub_mul_digits(a: &mut [Digit], b: &BigUintSlice, c: Digit) {
    debug_assert!(a.len() == b.len() + 2);

    let c = c as DoubleDigit;
    let mut mul_carry: DoubleDigit = 0;
    let mut sub_borrow = false;

    let mut a_mut = a.iter_mut();
    for b_digit in b {
        let t = (*b_digit as DoubleDigit) * c + mul_carry;
        mul_carry = t >> DIGIT_BITS;

        let a_digit = a_mut.next().unwrap();
        (*a_digit, sub_borrow) = borrowing_sub(*a_digit, t as Digit, sub_borrow);
    }

    // the second most significant digit of `a`.
    let a_digit = a_mut.next().unwrap();
    (*a_digit, sub_borrow) = borrowing_sub(*a_digit, mul_carry as Digit, sub_borrow);

    // the most significant digit of `a`.
    let a_digit = a_mut.next().unwrap();
    *a_digit = borrowing_sub(*a_digit, 0, sub_borrow).0;
}

/// a += b
#[inline]
fn assign_add_digits(a: &mut [Digit], b: &BigUintSlice) {
    debug_assert!(a.len() == b.len() + 2);

    let mut carry = false;

    let mut a_mut = a.iter_mut();
    for b_digit in b {
        let a_digit = a_mut.next().unwrap();
        (*a_digit, carry) = carrying_add(*a_digit, *b_digit, carry);
    }

    // the second most significant digit of `a`.
    let a_digit = a_mut.next().unwrap();
    (*a_digit, carry) = carrying_add(*a_digit, 0, carry);

    // the most significant digit of `a`.
    let a_digit = a_mut.next().unwrap();
    *a_digit = carrying_add(*a_digit, 0, carry).0;
}

/// Returns the length of the largest possible quotient of an division operation.
///
/// `dividend_len` is the length of the dividend.
#[inline]
fn div_rem_quotient_max_len(dividend_len: usize) -> usize {
    dividend_len
}

/// Creates a `DigitVec` which can be used as quotient of an division operation.
///
/// `a_len` and `b_len` are the length of the operands.
#[inline]
fn digitvec_div_rem_quotient(dividend_len: usize) -> DigitVec {
    let max_len = div_rem_quotient_max_len(dividend_len);
    digitvec_with_len(max_len)
}

/// Returns the length of the largest possible remainder of an division operation.
///
/// `divisor_len` is the length of the divisor.
#[inline]
fn div_rem_remainder_max_len(divisor_len: usize) -> usize {
    divisor_len
}

/// Creates a `DigitVec` which can be used as remainder of an division operation.
///
/// `divisor_len` is the length of the divisor.
#[inline]
fn digitvec_div_rem_remainder(divisor_len: usize) -> DigitVec {
    let max_len = div_rem_remainder_max_len(divisor_len);
    digitvec_with_len(max_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing_tools::quickcheck::BigIntHexString;
    use quickcheck::{Gen, QuickCheck};

    #[test]
    #[should_panic(expected = "attempt to divide by zero")]
    fn test_divisor_is_zero() {
        let _ = BigInt::from(123) / BigInt::from(0);
    }

    #[test]
    fn test_div_cases() {
        let data = [
            // `r_hat > Digit::MAX` for `Digit` is u8
            ("4e432fBecBAF6B2EfE401dC31caC3C74b46cB1ACc826", "D0F8C7ae"),

            // dividend is zero
            ("00", "D0F8"),

            // dividend equals divisor
            ("4e432fBe", "4e432fBe"),

            // dividend less than divisor
            ("D0F8C7ae", "4e432fBecBAF6B2EfE401dC31caC3C74b46cB1ACc826"),

            // one-digit divisor
            ("4e432fBecBAF6B2EfE401dC31caC3C74b46cB1ACc826", "C7"),

            // ``q_hat - 3 == q`` for `Digit` is u8
            ("DF9D8de0aDBCcC5effc99f39b8Cfe2Db8F4294dDf77B849ce548546d2fc4D3fEb6FdCe40ebBe2B8eAFcC01",
            "01eca5aE9Cc7"),
        ];
        for (a_hex, b_hex) in data {
            let a = BigInt::try_from(a_hex).unwrap();
            let b = BigInt::try_from(b_hex).unwrap();

            let quotient = &a / &b;
            let remainder = &a % &b;
            let mul_add_result = &quotient * &b + &remainder;
            assert_eq!(mul_add_result, a)
        }
    }

    #[test]
    fn test_devrem_with_muladd() {
        #[cfg(not(u8_digit))]
        const TEST_NUMBER: u64 = 10000;
        #[cfg(u8_digit)]
        const TEST_NUMBER: u64 = 6000;

        #[cfg(not(u8_digit))]
        const GEN_SIZE: usize = 1000;
        #[cfg(u8_digit)]
        const GEN_SIZE: usize = 200;

        fn prop(dividend_hex: BigIntHexString, divisor_hex: BigIntHexString) -> bool {
            let dividend = BigInt::from_hex(&dividend_hex.0).unwrap();
            let divisor = BigInt::from_hex(&divisor_hex.0).unwrap();
            if divisor == BigInt::from(0) {
                return true; // just ignore
            }

            let quotient = &dividend / &divisor;
            let remainder = &dividend % &divisor;

            let mul_add_result = &quotient * &divisor + &remainder;
            dividend == mul_add_result
        }

        QuickCheck::new()
            .gen(Gen::new(GEN_SIZE))
            .tests(TEST_NUMBER)
            .quickcheck(prop as fn(BigIntHexString, BigIntHexString) -> bool)
    }
}
