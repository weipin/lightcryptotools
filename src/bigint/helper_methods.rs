// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements functions required for creating big integer implementations.
//!
//! Follows the Rust nightly feature [`bigint_helper_methods`][1]
//!
//! [1]: https://github.com/rust-lang/rust/issues/85532

use super::digit::Digit;

/// Calculates `self + rhs + carry` without the ability to overflow.
///
/// Performs "ternary addition" which takes in an extra bit to add, and may return an
/// additional bit of overflow. This allows for chaining together multiple additions
/// to create "big integers" which represent larger values.
///
/// Adapted from [nightly][1]:
///
/// [1]: https://github.com/clarfonthey/rust/blob/cc15047d505c2cb6bba7475b18450f9785a78d7e/library/core/src/num/uint_macros.rs#L1381
#[inline]
pub(crate) fn carrying_add(lhs: Digit, rhs: Digit, carry: bool) -> (Digit, bool) {
    let (a, b) = lhs.overflowing_add(rhs);
    let (c, d) = a.overflowing_add(carry as Digit);
    (c, b || d)
}

/// Calculates `self - rhs - borrow` without the ability to overflow.
///
/// Performs "ternary subtraction" which takes in an extra bit to subtract, and may return
/// an additional bit of overflow. This allows for chaining together multiple subtractions
/// to create "big integers" which represent larger values.
///
/// Adapted from [nightly][1]:
///
/// [1]: https://github.com/clarfonthey/rust/blob/cc15047d505c2cb6bba7475b18450f9785a78d7e/library/core/src/num/uint_macros.rs#L1436
#[inline]
pub(crate) fn borrowing_sub(lhs: Digit, rhs: Digit, borrow: bool) -> (Digit, bool) {
    let (a, b) = lhs.overflowing_sub(rhs);
    let (c, d) = a.overflowing_sub(borrow as Digit);
    (c, b || d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carrying_add() {
        assert_eq!(carrying_add(5, 2, false), (7, false));
        assert_eq!(carrying_add(5, 2, true), (8, false));
        assert_eq!(carrying_add(Digit::MAX, 1, false), (0, true));
        assert_eq!(carrying_add(Digit::MAX, 1, true), (1, true));
    }

    #[test]
    fn test_borrowing_sub() {
        assert_eq!(borrowing_sub(5, 2, false), (3, false));
        assert_eq!(borrowing_sub(5, 2, true), (2, false));
        assert_eq!(borrowing_sub(0, 1, false), (Digit::MAX, true));
        assert_eq!(borrowing_sub(0, 1, true), (Digit::MAX - 1, true));
    }
}
