// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Trait for data structure decoding (deserializing).
pub trait Decodable<'a, D: DecodingItem<'a>>: Sized {
    /// Decodes a `Self` from a `DecodingItem`.
    fn decode_from(decoding_item: &D) -> Result<Self, D::Error>;
}

/// Trait for providing the decoding operations.
pub trait DecodingItem<'a>: Sized {
    type Error;

    /// Creates a `DecodingItem` from `data`.
    /// Returns an Error if the initialization is unsuccessful.
    fn new_from_data(data: &'a [u8]) -> Result<Self, Self::Error>;
}
