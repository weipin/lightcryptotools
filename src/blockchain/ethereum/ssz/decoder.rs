// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides `DecodingItem` implementation for SSZ.

use crate::tools::codable::DecodingItem;
use std::error::Error;
use std::fmt;
use std::fmt::Display;

/// The SSZ decoding type which implements `DecodingItem`.
pub struct SszDecodingItem<'a> {
    pub data: &'a [u8],
}

impl<'a> DecodingItem<'a> for SszDecodingItem<'a> {
    type Error = SszDataDecodingError;

    fn new_from_data(data: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(SszDecodingItem { data })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SszDataDecodingError {
    InvalidFormat,
}

impl Display for SszDataDecodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SszDataDecodingError::InvalidFormat => {
                write!(f, "Invalid format")
            }
        }
    }
}

impl Error for SszDataDecodingError {}
