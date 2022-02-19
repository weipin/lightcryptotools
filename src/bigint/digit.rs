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

pub type Digit = u64;
pub(crate) type DoubleDigit = u128;

pub(crate) const DIGIT_BITS: u32 = Digit::BITS;
pub const DIGIT_BYTES: u32 = DIGIT_BITS / 8;

#[cfg(test)]
mod tests {
    use super::Digit;

    #[test]
    #[allow(unused_comparisons)]
    fn digit_is_unsigned() {
        assert!(Digit::MIN >= 0);
    }
}
