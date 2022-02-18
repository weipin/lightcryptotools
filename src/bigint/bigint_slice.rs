// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_core::BigInt;
use super::digit::Digit;
use super::len::len_digits;

/// An array of digits representing a big unsigned integer.
///
/// - Must not be empty, e.g., zero is represented by `[0]`, not `[]`.
/// - Digits are stored in little-endian order.
/// - Must not have any zero padding, that is: `assert_eq!(len_digits(a), a.len())`.
/// - Does not have a sign.
pub(crate) type BigUintSlice = [Digit];

#[inline]
pub(crate) fn is_valid_biguint_slice(slice: &BigUintSlice) -> bool {
    !slice.is_empty() && (len_digits(slice) == slice.len())
}

impl BigInt {
    /// Returns a `BigUintSlice` of this `BigInt`'s digits.
    pub(crate) fn as_digits(&self) -> &BigUintSlice {
        debug_assert!(self.digits_len > 0);
        &self.digits_storage[..self.digits_len]
    }
}
