// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_core::BigInt;
use super::bytes::digits_to_bytes_be;
use crate::crypto::bytes_to_hex;
use std::fmt;
use std::fmt::Display;

impl Display for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Reverses `digits`, for the hex representation is in big-endian order.
        let mut digits_be = self.as_digits().to_vec();
        digits_be.reverse();

        let bytes = digits_to_bytes_be(&digits_be);
        let hex = bytes_to_hex(&bytes);
        write!(f, "0x{hex}")
    }
}
