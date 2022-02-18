// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::digit::Digit;

/// A vector to store digits representing a big unsigned integer.
pub(crate) type DigitVec = Vec<Digit>;

/// Creates a zeroed `DigitVec` with the specified `len`.
#[inline]
pub(crate) fn digitvec_with_len(len: usize) -> DigitVec {
    debug_assert!(len > 0);

    vec![0; len]
}

/// Creates a `DigitVec` with the specified digits.
///
/// The digits must be specified in big-endian order.
#[cfg(test)]
macro_rules! digits_be {
    ( $( $x:expr ),* ) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push($x);
            )*
            temp_vec.reverse();
            temp_vec
        }
    };
}

#[cfg(test)]
pub(crate) use digits_be;
