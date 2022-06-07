// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Functions to encode (serialize) or decode (deserialize) Rust data structures.

use super::decodable::{Decodable, DecodingItem};
use super::encodable::{Encodable, EncodingItem};

/// Encodes `value` to bytes.
pub fn encode<T: Encodable<E>, E: EncodingItem>(value: &T) -> Vec<u8> {
    let mut root_encoding_item = E::new();
    value.encode_to(&mut root_encoding_item);

    root_encoding_item.take_data()
}

/// Decodes a `T` from `data`.
pub fn decode<'a, T: Decodable<'a, D>, D: DecodingItem<'a>>(
    data: &'a [u8],
) -> Result<T, D::Error> {
    let root_decoding_item = D::new_from_data(data)?;
    T::decode_from(&root_decoding_item)
}
