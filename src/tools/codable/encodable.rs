// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Trait for data structure encoding (serializing).
pub trait Encodable<E: EncodingItem> {
    /// Encodes `self` to a `EncodingItem`.
    fn encode_to(&self, encoding_item: &mut E);
}

/// Trait for providing the encoding operations.
pub trait EncodingItem {
    fn new() -> Self;

    /// Returns encoded data and resets the internal state.
    fn take_data(&mut self) -> Vec<u8>;
}
