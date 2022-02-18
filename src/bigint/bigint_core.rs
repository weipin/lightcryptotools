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
#[derive(Debug)]
pub struct BigInt {
    pub(crate) digits_storage: Vec<Digit>,
    pub(crate) digits_len: usize, // The length of digits stored in `digits_storage`
    // TODO: remove allow
    #[allow(dead_code)]
    pub(crate) sign: Sign,
}

/// Denotes the sign of a big integer.
///
/// A big integer, including 0, can be denoted as either positive or negative.
#[derive(Debug)]
pub enum Sign {
    Positive,
}
