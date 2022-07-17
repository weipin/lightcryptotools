// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines `BigInt`.

use super::digit::Digit;

/// A big integer.
///
/// Digits are stored in little-endian order,
/// e.g., the "least significant digit" is stored at position 0.
#[derive(Clone, Debug)]
pub struct BigInt {
    pub(crate) digits_storage: Vec<Digit>,
    pub(crate) digits_len: usize, // The length of digits stored in `digits_storage`
    pub(crate) sign: Sign,
}

impl BigInt {
    pub(crate) fn is_sign_negative(&self) -> bool {
        self.sign == Sign::Negative
    }
}

/// Denotes the sign of a big integer.
///
/// A big integer, including 0, can be denoted as either positive or negative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sign {
    Positive,
    Negative,
}
