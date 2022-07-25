// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::decoder::{SszDataDecodingError, SszDecodingItem};
use super::encoder::SszEncodingItem;
use crate::tools::codable::{Decodable, Encodable};

pub trait SszType: Sized {
    /// Returns `None` if the type is "variable-size".
    /// Returns the size of the type in bytes if the type is "fixed-size".
    fn size() -> Option<u32>;

    /// Return the memory representation of `self` as a byte array.
    fn to_bytes(&self) -> Vec<u8>;

    /// Creates `Self` from `bytes`.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError>;
}

impl<T: SszType> Encodable<SszEncodingItem> for T {
    fn encode_to(&self, encoding_item: &mut SszEncodingItem) {
        debug_assert!(
            encoding_item.is_empty(),
            "Use `encode_as_container_element` to encode a container element"
        );
        encoding_item.encode_fixed_size_data(&self.to_bytes());
    }
}

impl<'a, T: SszType> Decodable<'a, SszDecodingItem<'a>> for T {
    fn decode_from(decoding_item: &SszDecodingItem<'a>) -> Result<Self, SszDataDecodingError> {
        T::try_from_bytes(decoding_item.data)
    }
}

/// Number of bytes per serialized length offset. See the spec.
pub(crate) const BYTES_PER_LENGTH_OFFSET: u32 = 4;
