// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::add::add_digits;
use crate::bigint::bigint_core::{BigInt, Sign};
use crate::bigint::bigint_slice::BigUintSlice;
use crate::bigint::bigint_vec::{digitvec_with_len, DigitVec};
use crate::bigint::cmp::cmp_digits;
use crate::bigint::digit::Digit;
use crate::bigint::divrem::div_rem_digits;
use crate::bigint::mul::mul_digits;
use crate::bigint::sub::sub_digits;
use crate::bigint::zero::is_zero_digits;
use std::cmp::Ordering;

/// Computes the greatest common divisor(GCD) of `a` and `b`.
/// Returns (x, y, v) such that xa + yb = v, where v = gcd(a, b).
///
/// `a` must be greater than `b` (a > b), and `b` must be greater than 0 (b > 0).
pub(crate) fn gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    assert!(a > b);
    assert!(b > &BigInt::zero());

    let ((y_digits, y_len, y_sign), (v_digits, v_len)) =
        gcd_digits(a.as_digits(), b.as_digits());
    let y = BigInt::new(y_digits, y_len, y_sign);
    let v = BigInt::new(v_digits, v_len, Sign::Positive);
    // xa + yb = v
    // x = (v - yb) / a
    let x = (&v - &y * b) / a;

    (x, y, v)
}

/// Returns (y, v) such that (x?)a + yb = v, where v = gcd(a, b)
///
/// a > b
fn gcd_digits(
    a: &BigUintSlice,
    b: &BigUintSlice,
) -> ((DigitVec, usize, Sign), (DigitVec, usize)) {
    // Employs extended Euclidean algorithm to compute the greatest common divisor(GCD).
    // Also employs Lehmer's "digit partial cosequeuce calculation"(DPCC) for performance.
    //
    // Besides, uses Collins's condition (only one quotient has to be computed) to
    // determine if `q_hat` is correct.
    //
    // To handle the overflow of signed single-precision integer during DPCC,
    // an extra boolean condition is introduced. The condition respects the fact that
    // "the signs of the elements of each cosequence alternate:", that is:
    // odd iteration: v0 >= 0, v1 <= 0, v2 >= 0
    // even iteration: v0 <= 0, v1 >= 0, v2 <= 0
    //
    // References
    // - Collins: G. E. Collins. Lecture notes on arithmetic algorithms, 1980. Univ. of Wisconsin
    // - Jebelean: Improving the Multiprecision Euclidean Algorithm
    // - HAC: Handbook of Applied Cryptography
    // - HEHCC: Handbook of Elliptic and Hyperelliptic Curve Cryptography
    // - ACP2: Art of Computer Programming, Volume 2: Seminumerical Algorithms
    //
    // TODO: implements improvements from Jebelean and Lercier.
    // TODO: See HEHCC, 10.6.2 Lehmer extended gcd

    assert_eq!(cmp_digits(a, b), Ordering::Greater); // a > b
    assert!(!is_zero_digits(b)); // b != 0

    let mut a = a.to_vec();
    let mut a_len = a.len();
    let mut b = b.to_vec();
    let mut b_len = b.len();

    // The code and part of the variable naming convention follow HEHCC, Algorithm 10.42.
    // Throughout the algorithm, the digit length of `ua` and `ub` won't exceed `a_len`.
    // See HEHCC Remarks 10.43 (ii)
    let mut ua = digitvec_with_len(a_len);
    let mut ub = digitvec_with_len(a_len);

    // ua = 0
    let mut ua_len = 1;
    let mut ua_sign = Sign::Positive;
    // ub = 1
    *ub.first_mut().unwrap() = 1;
    let mut ub_len = 1;
    let mut ub_sign = Sign::Positive;

    // To store multiplication results of `[u0|u1|v0|v1] * [a|b|ua|ub]`
    let mut x_mul_digits1 = digitvec_with_len(a_len + 1);
    let mut y_mul_digits2 = digitvec_with_len(a_len + 1);

    // To store intermediate digits of `[a|b|ua|ub]`.
    // +1 to match the digit length of `x_mul_digits1` and `y_mul_digits2`.
    let mut digits_t1 = digitvec_with_len(a_len + 1);
    let mut digits_t2 = digitvec_with_len(a_len + 1);

    // To store `a / b`.
    let mut q_digits = digitvec_with_len(a_len);

    // To store `q * b` or `q * ub`
    let mut q_mul_ua_digits = digitvec_with_len(a_len * 2);

    // To store `a - q * b` or `ua - q * ub`
    let mut q_mul_ua_t_digits = digitvec_with_len(a_len * 2);

    // To store `a % b` (the resulting remainder isn't used).
    // The parameter `remainder` of the function `div_rem_digits` cannot be omitted,
    // and so this variable is necessary for now.
    let mut remainder_digits = digitvec_with_len(b_len);

    // The condition introduced to handle the overflow of single-precision integer.
    let mut dpcc_iteration_odd;

    let mut u0: Digit;
    let mut u1: Digit;
    let mut u2: Digit;
    let mut v0: Digit;
    let mut v1: Digit;
    let mut v2: Digit;

    while !is_zero_digits(&b[..b_len]) {
        // When the digit length of `b` is greater than 1,
        // do the "digit partial cosequeuce calculation"(DPCC).
        let dpcc = b_len > 1;
        if dpcc {
            dpcc_iteration_odd = true;

            // Sets the variables to the "pre-initial" state.
            // Only after the first successful DPCC iteration, these variables are then
            // in the "initial state" as the algorithm describes:
            // u0 = 1, u1 = 0, v0 = 0, v1 = 1.
            (u0, u1, u2) = (0, 1, 0);
            (v0, v1, v2) = (0, 0, 1);

            // `a_hat` and `b_hat` are the most significant `Digit::BITS` bits of `a` and `b`.
            //
            // In other words, let `a_hat` be the `Digit::BITS` leading bits of `a`,
            // and let `b_hat` be the corresponding bits of `b`.
            // `a_hat` = ⌊a / 2^k⌋ and `b_hat` = ⌊b / 2^k⌋,
            // where k is as small as possible consistent with the condition `a_hat` < Digit::MAX.
            //
            // For details, see ACP2, Algorithm L.
            let msd = a[a_len - 1];
            let second_msd = a[a_len - 2];
            let t = msd.leading_zeros();
            let mut a_hat = msd << t | second_msd.checked_shr(Digit::BITS - t).unwrap_or(0);

            let mut b_hat = match a_len - b_len {
                0 => {
                    let msd = b[b_len - 1];
                    let second_msd = b[b_len - 2];
                    msd << t | second_msd.checked_shr(Digit::BITS - t).unwrap_or(0)
                }
                1 => {
                    let msd = b[b_len - 1];
                    msd.checked_shr(Digit::BITS - t).unwrap_or(0)
                }
                _ => 0,
            };

            // Collins's condition check.
            // While I failed to locate the paper on internet,
            // Jebelean's paper mentions the condition(9):
            //
            // v2 = v0 - q * v1
            // b_hat >= |v2| && a_hat - b_hat >= |v1 - v2|
            //
            // Note: the condition above involves signed single-precision integer `v0`, `v1`, and `v2`.
            // And in the code below, variables `v0`, `v1`, and `v2` are all unsigned integers with type `Digit`.
            // You can translate the variables `v0`, `v1` and `v2` as |v0|, |v1| and |v2|.
            //
            // Signs alternating:
            // odd iteration: v0 >= 0, v1 <= 0, v2 >= 0
            // even iteration: v0 <= 0, v1 >= 0, v2 <= 0
            //
            // 1) To calculate |v2|, use code `v2 = v0 + q * v1`
            // |v2| = |v0 - q * v1|
            // Takes the signs alternating into account:
            // odd: |v0| - q * -|v1| = |v0| + q * |v1|
            // even: -(-|v0| - q * |v1|) = |v0| + q * |v1|
            //
            // 2) To calculate |v1 - v2|, use code `v1 + v2`
            // Takes the signs alternating into account:
            // odd: -(-|v1| - |v2|) = |v1| + |v2|
            // even: |v1| - -|v2| = |v1| + |v2|
            //
            // 3) Also, (|v1| + |v2|) < Digit::MAX
            // |v1| + |v2| <= |v1| + q * |v2| = |v3| < Digit::MAX
            while b_hat >= v2 && a_hat - b_hat >= v1 + v2 {
                let (q, r) = (a_hat / b_hat, a_hat % b_hat);
                a_hat = b_hat;
                b_hat = r;

                (u0, u1, u2) = (u1, u2, u1 + q * u2);
                (v0, v1, v2) = (v1, v2, v1 + q * v2);

                dpcc_iteration_odd = !dpcc_iteration_odd;
            }

            if v0 == 0 {
                // Invalid DPCC and the initial state cannot be fulfilled. See sample `gcd(768454923, 542167814)`.
                // Falls back to extended Euclidean algorithm.
                iterate_euclid_extended(
                    &mut a,
                    &mut a_len,
                    &mut b,
                    &mut b_len,
                    &mut ua,
                    &mut ua_len,
                    &mut ua_sign,
                    &mut ub,
                    &mut ub_len,
                    &mut ub_sign,
                    &mut q_digits,
                    &mut remainder_digits,
                    &mut q_mul_ua_digits,
                    &mut q_mul_ua_t_digits,
                );
            } else {
                #[allow(clippy::collapsible_else_if)]
                if dpcc_iteration_odd {
                    iterate_dpcc_a_and_b_odd(
                        &mut a,
                        &mut a_len,
                        &mut b,
                        &mut b_len,
                        u0,
                        u1,
                        v0,
                        v1,
                        &mut x_mul_digits1,
                        &mut y_mul_digits2,
                        &mut digits_t1,
                        &mut digits_t2,
                    );
                    iterate_dpcc_ua_and_ub_odd(
                        &mut ua,
                        &mut ua_len,
                        &mut ua_sign,
                        &mut ub,
                        &mut ub_len,
                        &mut ub_sign,
                        u0,
                        u1,
                        v0,
                        v1,
                        &mut x_mul_digits1,
                        &mut y_mul_digits2,
                        &mut digits_t1,
                        &mut digits_t2,
                    );
                } else {
                    iterate_dpcc_a_and_b_even(
                        &mut a,
                        &mut a_len,
                        &mut b,
                        &mut b_len,
                        u0,
                        u1,
                        v0,
                        v1,
                        &mut x_mul_digits1,
                        &mut y_mul_digits2,
                        &mut digits_t1,
                        &mut digits_t2,
                    );
                    iterate_dpcc_ua_and_ub_even(
                        &mut ua,
                        &mut ua_len,
                        &mut ua_sign,
                        &mut ub,
                        &mut ub_len,
                        &mut ub_sign,
                        u0,
                        u1,
                        v0,
                        v1,
                        &mut x_mul_digits1,
                        &mut y_mul_digits2,
                        &mut digits_t1,
                        &mut digits_t2,
                    );
                } // dpcc_iteration_odd
            } // v0 == 0
        } else {
            // Employs the extended Euclidean algorithm, for DPCC isn't appropriate.
            iterate_euclid_extended(
                &mut a,
                &mut a_len,
                &mut b,
                &mut b_len,
                &mut ua,
                &mut ua_len,
                &mut ua_sign,
                &mut ub,
                &mut ub_len,
                &mut ub_sign,
                &mut q_digits,
                &mut remainder_digits,
                &mut q_mul_ua_digits,
                &mut q_mul_ua_t_digits,
            );
        } // dpcc
    } // b != 0

    // y = ua
    // z = a
    ((ua, ua_len, ua_sign), (a, a_len))
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
/// Iterates DPCC and updates `a` and `b` (odd).
///
/// `x_mul_digits1`, `y_mul_digits2`, `digits_t1` and `digits_t2` are used to store intermediate digits.
fn iterate_dpcc_a_and_b_odd(
    a: &mut [Digit],
    a_len: &mut usize,
    b: &mut [Digit],
    b_len: &mut usize,
    u0: Digit,
    u1: Digit,
    v0: Digit,
    v1: Digit,
    x_mul_digits1: &mut [Digit],
    y_mul_digits2: &mut [Digit],
    digits_t1: &mut [Digit],
    digits_t2: &mut [Digit],
) {
    // a = (-u0)*a + v0*b = v0*b - u0*a
    let digits_t1_len = x_mul_digits1_sub_y_mul_digits2_unsigned(
        v0,
        &b[..*b_len],
        u0,
        &a[..*a_len],
        x_mul_digits1,
        y_mul_digits2,
        digits_t1,
    );
    // b = u1*a + (-v1)*b = u1*a - v1*b
    let digits_t2_len = x_mul_digits1_sub_y_mul_digits2_unsigned(
        u1,
        &a[..*a_len],
        v1,
        &b[..*b_len],
        x_mul_digits1,
        y_mul_digits2,
        digits_t2,
    );

    a.fill(0);
    a[..digits_t1_len].copy_from_slice(&digits_t1[..digits_t1_len]);
    *a_len = digits_t1_len;

    b.fill(0);
    b[..digits_t2_len].copy_from_slice(&digits_t2[..digits_t2_len]);
    *b_len = digits_t2_len;
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
/// Iterates DPCC and updates `a` and `b` (even).
///
/// `x_mul_digits1`, `y_mul_digits2`, `digits_t1` and `digits_t2` are used to store intermediate digits.
fn iterate_dpcc_a_and_b_even(
    a: &mut [Digit],
    a_len: &mut usize,
    b: &mut [Digit],
    b_len: &mut usize,
    u0: Digit,
    u1: Digit,
    v0: Digit,
    v1: Digit,
    x_mul_digits1: &mut [Digit],
    y_mul_digits2: &mut [Digit],
    digits_t1: &mut [Digit],
    digits_t2: &mut [Digit],
) {
    // a = u0*a + (-v0)*b = u0*a - v0*b
    let digits_t1_len = x_mul_digits1_sub_y_mul_digits2_unsigned(
        u0,
        &a[..*a_len],
        v0,
        &b[..*b_len],
        x_mul_digits1,
        y_mul_digits2,
        digits_t1,
    );
    // b = (-u1)*a + v1*b = v1*b - u1*a
    let digits_t2_len = x_mul_digits1_sub_y_mul_digits2_unsigned(
        v1,
        &b[..*b_len],
        u1,
        &a[..*a_len],
        x_mul_digits1,
        y_mul_digits2,
        digits_t2,
    );

    a.fill(0);
    a[..digits_t1_len].copy_from_slice(&digits_t1[..digits_t1_len]);
    *a_len = digits_t1_len;

    b.fill(0);
    b[..digits_t2_len].copy_from_slice(&digits_t2[..digits_t2_len]);
    *b_len = digits_t2_len;
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
/// Iterates DPCC and updates `ua` and `ub` (odd).
///
/// `x_mul_digits1`, `y_mul_digits2`, `digits_t1` and `digits_t2` are used to store intermediate digits.
fn iterate_dpcc_ua_and_ub_odd(
    ua: &mut [Digit],
    ua_len: &mut usize,
    ua_sign: &mut Sign,
    ub: &mut [Digit],
    ub_len: &mut usize,
    ub_sign: &mut Sign,
    u0: Digit,
    u1: Digit,
    v0: Digit,
    v1: Digit,
    x_mul_digits1: &mut [Digit],
    y_mul_digits2: &mut [Digit],
    digits_t1: &mut [Digit],
    digits_t2: &mut [Digit],
) {
    // ua = (-u0)*ua + v0*ub = v0*ub - u0*ua
    let (digits_t1_len, digits_t1_sign) = x_mul_digits1_sub_y_mul_digits2_signed(
        v0,
        &ub[..*ub_len],
        *ub_sign,
        u0,
        &ua[..*ua_len],
        *ua_sign,
        x_mul_digits1,
        y_mul_digits2,
        digits_t1,
    );
    // ub = u1*ua + (-v1)*ub = u1*ua - v1*ub
    let (digits_t2_len, digits_t2_sign) = x_mul_digits1_sub_y_mul_digits2_signed(
        u1,
        &ua[..*ua_len],
        *ua_sign,
        v1,
        &ub[..*ub_len],
        *ub_sign,
        x_mul_digits1,
        y_mul_digits2,
        digits_t2,
    );
    ua.fill(0);
    ua[..digits_t1_len].copy_from_slice(&digits_t1[..digits_t1_len]);
    *ua_len = digits_t1_len;
    *ua_sign = digits_t1_sign;

    ub.fill(0);
    ub[..digits_t2_len].copy_from_slice(&digits_t2[..digits_t2_len]);
    *ub_len = digits_t2_len;
    *ub_sign = digits_t2_sign;
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
/// Iterates DPCC and updates `ua` and `ub` (even).
///
/// `x_mul_digits1`, `y_mul_digits2`, `digits_t1` and `digits_t2` are used to store intermediate digits.
fn iterate_dpcc_ua_and_ub_even(
    ua: &mut [Digit],
    ua_len: &mut usize,
    ua_sign: &mut Sign,
    ub: &mut [Digit],
    ub_len: &mut usize,
    ub_sign: &mut Sign,
    u0: Digit,
    u1: Digit,
    v0: Digit,
    v1: Digit,
    x_mul_digits1: &mut [Digit],
    y_mul_digits2: &mut [Digit],
    digits_t1: &mut [Digit],
    digits_t2: &mut [Digit],
) {
    // ua = u0*ua + (-v0)*ub = u0*ua - v0*ub
    let (digits_t1_len, digits_t1_sign) = x_mul_digits1_sub_y_mul_digits2_signed(
        u0,
        &ua[..*ua_len],
        *ua_sign,
        v0,
        &ub[..*ub_len],
        *ub_sign,
        x_mul_digits1,
        y_mul_digits2,
        digits_t1,
    );
    // ub = (-u1)*ua + v1*ub = v1*ub - u1*ua
    let (digits_t2_len, digits_t2_sign) = x_mul_digits1_sub_y_mul_digits2_signed(
        v1,
        &ub[..*ub_len],
        *ub_sign,
        u1,
        &ua[..*ua_len],
        *ua_sign,
        x_mul_digits1,
        y_mul_digits2,
        digits_t2,
    );

    ua.fill(0);
    ua[..digits_t1_len].copy_from_slice(&digits_t1[..digits_t1_len]);
    *ua_len = digits_t1_len;
    *ua_sign = digits_t1_sign;

    ub.fill(0);
    ub[..digits_t2_len].copy_from_slice(&digits_t2[..digits_t2_len]);
    *ub_len = digits_t2_len;
    *ub_sign = digits_t2_sign;
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
/// Iterates extended Euclidean algorithm and updates `a`, `b`, `ua` and `ub`.
///
/// `q_digits`, `remainder_digits`, `q_mul_ua_digits` and `q_mul_ua_t_digits` are used to store intermediate digits.
fn iterate_euclid_extended(
    a: &mut [Digit],
    a_len: &mut usize,
    b: &mut [Digit],
    b_len: &mut usize,
    ua: &mut [Digit],
    ua_len: &mut usize,
    ua_sign: &mut Sign,
    ub: &mut [Digit],
    ub_len: &mut usize,
    ub_sign: &mut Sign,
    q_digits: &mut [Digit],
    remainder_digits: &mut [Digit],
    q_mul_ua_digits: &mut [Digit],
    q_mul_ua_t_digits: &mut [Digit],
) {
    // q = a / b
    let (q_digits_len, _) = div_rem_digits(
        &a[..*a_len],
        &b[..*b_len],
        q_digits,
        &mut remainder_digits[..*b_len],
    );
    // t = a - q * b
    let q_mul_ua_t_digits_len = a_sub_q_mul_b(
        &a[..*a_len],
        &q_digits[..q_digits_len],
        &b[..*b_len],
        q_mul_ua_digits,
        q_mul_ua_t_digits,
    );
    // a = b
    a.fill(0);
    a[..*b_len].copy_from_slice(&b[..*b_len]);
    *a_len = *b_len;
    // b = t
    b.fill(0);
    b[..q_mul_ua_t_digits_len].copy_from_slice(&q_mul_ua_t_digits[..q_mul_ua_t_digits_len]);
    *b_len = q_mul_ua_t_digits_len;

    // t = ua - q * ub
    let (q_mul_ua_t_digits_len, q_mul_ua_t_digits_sign) = ua_sub_q_mul_ub(
        &ua[..*ua_len],
        *ua_sign,
        &q_digits[..q_digits_len],
        &ub[..*ub_len],
        *ub_sign,
        q_mul_ua_digits,
        q_mul_ua_t_digits,
    );
    // ua = ub
    ua.fill(0);
    ua[..*ub_len].copy_from_slice(&ub[..*ub_len]);
    *ua_len = *ub_len;
    *ua_sign = *ub_sign;
    // ub = t
    ub.fill(0);
    ub[..q_mul_ua_t_digits_len].copy_from_slice(&q_mul_ua_t_digits[..q_mul_ua_t_digits_len]);
    *ub_len = q_mul_ua_t_digits_len;
    *ub_sign = q_mul_ua_t_digits_sign;
}

/// result = x * digits1 - y * digits2 > 0
#[inline(always)]
fn x_mul_digits1_sub_y_mul_digits2_unsigned(
    x: Digit,
    digits1: &BigUintSlice,
    y: Digit,
    digits2: &BigUintSlice,
    x_mul_digits1: &mut [Digit],
    y_mul_digits2: &mut [Digit],
    result: &mut [Digit],
) -> usize {
    let x_mul_digits1_len = mul_digits(&[x], digits1, x_mul_digits1);
    let y_mul_digits2_len = mul_digits(&[y], digits2, y_mul_digits2);

    sub_digits(
        &x_mul_digits1[..x_mul_digits1_len],
        &y_mul_digits2[..y_mul_digits2_len],
        result,
    )
}

/// result = x * digits1 - y * digits2
/// `digits1`, `digits2`, and `result` can be negative.
///
/// Returns the digit length and the sign of `result`.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn x_mul_digits1_sub_y_mul_digits2_signed(
    x: Digit,
    digits1: &BigUintSlice,
    digits1_sign: Sign,
    y: Digit,
    digits2: &BigUintSlice,
    digits2_sign: Sign,
    x_mul_digits1: &mut [Digit],
    y_mul_digits2: &mut [Digit],
    result: &mut [Digit],
) -> (usize, Sign) {
    let x_mul_digits1_len = mul_digits(&[x], digits1, x_mul_digits1);
    let y_mul_digits2_len = mul_digits(&[y], digits2, y_mul_digits2);
    let x_mul_digits1_slice = &x_mul_digits1[..x_mul_digits1_len];
    let y_mul_digits2_slice = &y_mul_digits2[..y_mul_digits2_len];

    if digits1_sign != digits2_sign {
        (
            add_digits(x_mul_digits1_slice, y_mul_digits2_slice, result),
            digits1_sign,
        )
    } else {
        match cmp_digits(x_mul_digits1_slice, y_mul_digits2_slice) {
            Ordering::Less => (
                sub_digits(y_mul_digits2_slice, x_mul_digits1_slice, result),
                -digits1_sign,
            ),
            Ordering::Equal => {
                result.fill(0);
                (1, Sign::Positive)
            }
            Ordering::Greater => (
                sub_digits(x_mul_digits1_slice, y_mul_digits2_slice, result),
                digits1_sign,
            ),
        }
    }
}

/// result = a - q * b > 0
/// Returns the digit length of `result`.
#[inline(always)]
fn a_sub_q_mul_b(
    a: &BigUintSlice,
    q: &BigUintSlice,
    b: &BigUintSlice,
    q_mul_b_digits: &mut [Digit],
    result: &mut [Digit],
) -> usize {
    let q_mul_b_digits_len = mul_digits(q, b, q_mul_b_digits);
    sub_digits(a, &q_mul_b_digits[..q_mul_b_digits_len], result)
}

/// result = ua - q * ub
/// Returns the digit length and the sign of `result`.
#[inline(always)]
fn ua_sub_q_mul_ub(
    ua: &BigUintSlice,
    ua_sign: Sign,
    q: &BigUintSlice,
    ub: &BigUintSlice,
    ub_sign: Sign,
    q_mul_ub_digits: &mut [Digit],
    result: &mut [Digit],
) -> (usize, Sign) {
    let q_mul_ub_digits_len = mul_digits(q, ub, q_mul_ub_digits);

    if ua_sign != ub_sign {
        (
            add_digits(ua, &q_mul_ub_digits[..q_mul_ub_digits_len], result),
            ua_sign,
        )
    } else {
        match cmp_digits(ua, &q_mul_ub_digits[..q_mul_ub_digits_len]) {
            Ordering::Less => (
                sub_digits(&q_mul_ub_digits[..q_mul_ub_digits_len], ua, result),
                -ua_sign,
            ),
            Ordering::Equal => {
                result.fill(0);
                (1, Sign::Positive)
            }
            Ordering::Greater => (
                sub_digits(ua, &q_mul_ub_digits[..q_mul_ub_digits_len], result),
                ua_sign,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing_tools::quickcheck::HexString;
    use quickcheck::{Gen, QuickCheck};
    use std::mem;

    #[test]
    fn test_gcd() {
        let data = [
            // a, b, v
            (17, 1, 1),
            (127, 45, 1),
            (693, 609, 21),
            (768454923, 542167814, 1),
        ];

        for (a, b, v) in data {
            let a = BigInt::from(a);
            let b = BigInt::from(b);
            let v = BigInt::from(v);

            let result = gcd(&a, &b);
            assert_eq!(result.2, v);
            assert_eq!(result.0 * &a + result.1 * &b, result.2);

            let result2 = gcd_euclid_extended(&a, &b);
            assert_eq!(result2.2, v);
            assert_eq!(result2.0 * &a + result2.1 * &b, result2.2);

            let result3 = gcd_binary_extended(&a, &b);
            assert_eq!(result3.2, v);
            assert_eq!(result3.0 * &a + result3.1 * &b, result3.2);
        }
    }

    #[test]
    #[should_panic]
    fn test_gcd_a_less_than_b() {
        gcd(&BigInt::from(7), &BigInt::from(17));
    }

    #[test]
    #[should_panic]
    fn test_gcd_a_equals_b() {
        gcd(&BigInt::from(7), &BigInt::from(7));
    }

    #[test]
    #[should_panic]
    fn test_gcd_b_equals_to_zero() {
        gcd(&BigInt::from(7), &BigInt::zero());
    }

    #[test]
    #[should_panic]
    fn test_gcd_b_less_than_zero() {
        gcd(&BigInt::from(7), &BigInt::from(-1));
    }

    #[test]
    #[should_panic]
    fn test_gcd_a_and_b_are_negative() {
        gcd(&BigInt::from(-7), &BigInt::from(-17));
    }

    #[test]
    #[should_panic]
    fn test_gcd_digits_a_less_than_b() {
        gcd_digits(&[7], &[17]);
    }

    #[test]
    #[should_panic]
    fn test_gcd_digits_a_equals_b() {
        gcd_digits(&[7], &[7]);
    }

    #[test]
    #[should_panic]
    fn test_gcd_digits_b_equals_to_zero() {
        gcd_digits(&[7], &[0]);
    }

    #[test]
    fn test_gcd_with_multiple_implementations() {
        const TEST_NUMBER: u64 = 1000;
        const GEN_SIZE: usize = 32;

        fn prop(a_hex: HexString, n_hex: HexString) -> bool {
            let mut a = BigInt::from_hex(&a_hex.0).unwrap();
            let mut b = BigInt::from_hex(&n_hex.0).unwrap();
            if a == b {
                return true;
            }
            if a < b {
                mem::swap(&mut a, &mut b);
            }
            if b.is_zero() {
                return true;
            }

            let (x, y, v) = gcd(&a, &b);

            // compares with other implementations
            let result1 = gcd_euclid_extended(&a, &b);
            let result2 = gcd_binary_extended(&a, &b);

            &x * &a + &y * &b == v && result1.2 == v && result2.2 == v
        }

        QuickCheck::new()
            .gen(Gen::new(GEN_SIZE))
            .tests(TEST_NUMBER)
            .quickcheck(prop as fn(HexString, HexString) -> bool)
    }

    /// Returns (a, b, v) such that ax + by = v, where v = gcd(x, y)
    fn gcd_binary_extended(x: &BigInt, y: &BigInt) -> (BigInt, BigInt, BigInt) {
        // Employs the binary extended gcd algorithm
        // For details see HAC, chapter 14
        // https://cacr.uwaterloo.ca/hac/about/chap14.pdf

        let mut g = BigInt::one();
        let mut x = x.clone();
        let mut y = y.clone();

        while x.is_even() && y.is_even() {
            x = &x >> 1;
            y = &y >> 1;
            g = &g << 1;
        }

        let mut u = x.clone();
        let mut v = y.clone();
        let mut a = BigInt::one();
        let mut b = BigInt::zero();
        let mut c = BigInt::zero();
        let mut d = BigInt::one();

        while !u.is_zero() {
            while u.is_even() {
                u = u >> 1;
                if a.is_even() && b.is_even() {
                    a = a >> 1;
                    b = b >> 1;
                } else {
                    a = (a + &y) >> 1;
                    b = (b - &x) >> 1;
                }
            }

            while v.is_even() {
                v = v >> 1;
                if c.is_even() && d.is_even() {
                    c = c >> 1;
                    d = d >> 1;
                } else {
                    c = (c + &y) >> 1;
                    d = (d - &x) >> 1;
                }
            }

            if u >= v {
                u = &u - &v;
                a = &a - &c;
                b = &b - &d;
            } else {
                v = &v - &u;
                c = &c - &a;
                d = &d - &b;
            }
        }

        (c, d, g * v)
    }

    /// Returns (v, u, d) such that ux + vn = d, where d = gcd(n, x)
    /// n > x
    fn gcd_euclid_extended(n: &BigInt, x: &BigInt) -> (BigInt, BigInt, BigInt) {
        // See HEHCC, Algorithm 10.42 Euclid extended gcd of positive integers
        debug_assert!(n > x);

        let mut a = n.clone();
        let mut b = x.clone();
        let mut ua = BigInt::zero();
        let mut ub = BigInt::one();

        while !b.is_zero() {
            let q = &a / &b;
            let t = &a - &q * &b;
            a = b;
            b = t;

            let t = &ua - &q * &ub;
            ua = ub;
            ub = t;
        }

        let v = (&a - x * &ua) / n;
        (v, ua, a)
    }
}
