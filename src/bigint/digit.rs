// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines "base" of multiple precision integers (big integers).
//!
//! Big integers are implemented as base b numbers.
//! While it is helpful to realize the situation when b = 10,
//! a Rust n-bit unsigned integer type is used as "digit".
//!
//! For any unsigned integer type chosen as digit,
//! a larger one must exist and be used as "double-digit".
//! Arithmetic operations will often be performed on the double-digit type.

#[cfg(not(u8_digit))]
pub type Digit = u64;
#[cfg(u8_digit)]
pub type Digit = u8;

#[cfg(not(u8_digit))]
pub(crate) type DoubleDigit = u128;
#[cfg(u8_digit)]
pub(crate) type DoubleDigit = u16;

pub const DIGIT_BYTES: u32 = Digit::BITS / 8;

#[cfg(test)]
mod tests {
    use super::Digit;

    #[test]
    #[allow(unused_comparisons)]
    fn digit_is_unsigned() {
        assert!(Digit::MIN >= 0);
    }
}
