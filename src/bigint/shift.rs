// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_core::BigInt;
use super::len::len_digits;
use crate::bigint::digit::Digit;
use std::iter::repeat;
use std::ops::{Shl, Shr};

fn shift_right(a: &mut BigInt, n: usize) {
    if n >= a.bit_len() {
        a.digits_storage.fill(0);
        a.digits_len = 1;
        return;
    }

    let digits = &mut a.digits_storage[..a.digits_len];
    let mut digits_len = a.digits_len;
    let shifting_digits_len = n / Digit::BITS as usize;
    let shifting_bits_len = n % Digit::BITS as usize;

    // Shifts in digit.
    if shifting_digits_len > 0 {
        digits[..shifting_digits_len].fill(0);
        digits.rotate_left(shifting_digits_len);
        digits_len -= shifting_digits_len;
    }

    // Shifts remaining bits.
    if shifting_bits_len > 0 {
        let next_shifting_bits_len = Digit::BITS as usize - shifting_bits_len;
        let mut carry = 0;
        for digit in digits[..digits_len].iter_mut().rev() {
            let t = *digit << next_shifting_bits_len;
            *digit = *digit >> shifting_bits_len | carry;
            carry = t;
        }
        digits_len = len_digits(digits);
    }

    a.digits_len = digits_len;
}

impl<'a> Shr<usize> for &'a BigInt {
    type Output = BigInt;

    fn shr(self, rhs: usize) -> Self::Output {
        let mut a = self.clone();
        shift_right(&mut a, rhs);
        a
    }
}

impl Shr<usize> for BigInt {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        (&self).shr(rhs)
    }
}

fn shift_left(a: &mut BigInt, n: usize) {
    let mut digits_len = a.digits_len;
    let shifting_digits_len = n / Digit::BITS as usize;
    let shifting_bits_len = n % Digit::BITS as usize;

    // Shifts in digit.
    if shifting_digits_len > 0 {
        let available_slots_len = a.digits_storage.len() - digits_len;
        if available_slots_len < shifting_digits_len {
            let iter = repeat(0).take(shifting_digits_len - available_slots_len);
            a.digits_storage.extend(iter);
        }

        digits_len += shifting_digits_len;
        a.digits_storage[..digits_len].rotate_right(shifting_digits_len);
    }

    // Shifts remaining bits.
    if shifting_bits_len > 0 {
        let next_shifting_bits_len = Digit::BITS as usize - shifting_bits_len;
        let mut carry = 0;
        if digits_len == a.digits_storage.len() {
            // Extends the storage for the possible carry at the most significant digit.
            a.digits_storage.push(0);
        }
        let digits = &mut a.digits_storage[..digits_len + 1];
        for digit in digits.iter_mut() {
            let t = *digit >> next_shifting_bits_len;
            *digit = *digit << shifting_bits_len | carry;
            carry = t;
        }
        digits_len = len_digits(digits);
    }

    a.digits_len = digits_len;
}

impl<'a> Shl<usize> for &'a BigInt {
    type Output = BigInt;

    fn shl(self, rhs: usize) -> Self::Output {
        let mut a = self.clone();
        shift_left(&mut a, rhs);
        a
    }
}

impl Shl<usize> for BigInt {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        (&self).shl(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing_tools::quickcheck::BigIntHexString;
    use ::quickcheck_macros::quickcheck;

    #[test]
    fn test_shift_right() {
        // 26 bytes (208 bits)
        let mut a =
            BigInt::from_hex("c8f14181b339ccd9092ce946d7a4c7ebc3708632ca4714ec67fb").unwrap();
        let mut b = a.clone();

        shift_right(&mut a, 0);
        assert_eq!(a, b);

        for _ in 0..208 {
            shift_right(&mut a, 1);
            b = b / BigInt::from(2);

            assert_eq!(a, b);
        }
        assert_eq!(a, BigInt::zero());
    }

    #[quickcheck]
    fn shift_right_compare_with_div(hex: BigIntHexString, n: u8) -> bool {
        let a = BigInt::from_hex(hex.0.as_str()).unwrap();
        let b = a.clone();

        // Limits shifting bits within [0, 2^4), so `divisor` won't overflow.
        let n = (n & 0x0f) as usize;
        let divisor = 2u32.pow(n as u32);

        let b = b / BigInt::from(divisor);
        a >> n == b
    }

    #[test]
    fn test_shift_left() {
        let mut a =
            BigInt::from_hex("c8f14181b339ccd9092ce946d7a4c7ebc3708632ca4714ec67fb").unwrap();
        let mut b = a.clone();

        shift_left(&mut a, 0);
        assert_eq!(a, b);

        for _ in 0..208 {
            shift_left(&mut a, 1);
            b = b * BigInt::from(2);

            assert_eq!(a, b);
        }
    }

    #[quickcheck]
    fn shift_left_compare_with_mul(hex: BigIntHexString, n: u8) -> bool {
        let a = BigInt::from_hex(hex.0.as_str()).unwrap();
        let b = a.clone();

        // Limits shifting bits within [0, 2^4), so `multiplicand` won't overflow.
        let n = (n & 0x0f) as usize;
        let multiplicand = 2u32.pow(n as u32);

        let b = b * BigInt::from(multiplicand);
        a << n == b
    }
}
