// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigUint;

/// Trait for data structure encoding (serializing).
pub trait Encodable<E: EncodingItem> {
    /// Encodes `self` to a `EncodingItem`.
    fn encode_to(&self, encoding_item: &mut E);
}

/// Trait for providing the encoding operations.
pub trait EncodingItem {
    fn new() -> Self;

    /// Encodes `n` and stores the result to the internal state.
    fn encode_u64(&mut self, n: u64);
    fn encode_biguint(&mut self, n: &BigUint);
    fn encode_str(&mut self, s: &str);
    fn encode_bytes(&mut self, bytes: &[u8]);
    fn encode_list_payload(&mut self, item: &mut Self);

    /// Returns encoded data and resets the internal state.
    fn take_data(&mut self) -> Vec<u8>;
}
