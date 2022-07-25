// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides `EncodingItem` implementation for SSZ.

use super::core::BYTES_PER_LENGTH_OFFSET;
use crate::tools::codable::EncodingItem;

enum HeaderType {
    FixedSizeObjectData(Vec<u8>),
    VariableSizeObjectDataRelativeOffset(u32),
}

/// The SSZ encoding type which implements `EncodingItem`.
pub struct SszEncodingItem {
    headers: Vec<HeaderType>,
    headers_byte_len: u32,
    encoded_variable_size_objects: Vec<u8>,
}

impl SszEncodingItem {
    /// Returns `true` if no data is encoded.
    pub(crate) fn is_empty(&self) -> bool {
        self.headers_byte_len == 0
    }

    pub(crate) fn encode_fixed_size_data(&mut self, bytes: &[u8]) {
        self.headers
            .push(HeaderType::FixedSizeObjectData(bytes.to_vec()));
        let bytes_len = u32::try_from(bytes.len()).unwrap();
        self.headers_byte_len = self.headers_byte_len.checked_add(bytes_len).unwrap();
    }

    pub(crate) fn encode_variable_size_data(&mut self, bytes: &[u8]) {
        let relative_offset = u32::try_from(self.encoded_variable_size_objects.len()).unwrap();

        self.headers
            .push(HeaderType::VariableSizeObjectDataRelativeOffset(
                relative_offset,
            ));
        self.headers_byte_len = self
            .headers_byte_len
            .checked_add(BYTES_PER_LENGTH_OFFSET)
            .unwrap();
        self.encoded_variable_size_objects.extend(bytes);
    }
}

impl EncodingItem for SszEncodingItem {
    fn new() -> SszEncodingItem {
        SszEncodingItem {
            headers: vec![],
            headers_byte_len: 0,
            encoded_variable_size_objects: vec![],
        }
    }

    fn take_data(&mut self) -> Vec<u8> {
        let mut data = Vec::with_capacity(
            self.headers_byte_len as usize + self.encoded_variable_size_objects.len(),
        );

        // Builds headers.
        for header in self.headers.drain(0..) {
            match header {
                HeaderType::FixedSizeObjectData(d) => {
                    data.extend(d);
                }
                HeaderType::VariableSizeObjectDataRelativeOffset(relative_offset) => {
                    let offset = relative_offset.checked_add(self.headers_byte_len).unwrap();
                    data.extend(offset.to_le_bytes());
                }
            }
        }

        // Builds "data".
        data.append(&mut self.encoded_variable_size_objects);
        self.headers_byte_len = 0;

        data
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::ethereum::ssz::SszEncodingItem;
    use crate::crypto::codecs::bytes_to_lower_hex;
    use crate::tools::codable::{Encodable, EncodingItem};

    #[test]
    fn test_take_data_emptying_internal_data() {
        let mut encoding_item = SszEncodingItem::new();
        12_u8.encode_to(&mut encoding_item);
        assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), "0c");

        // Reuses `encoding_item`
        19_u8.encode_to(&mut encoding_item);
        assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), "13");
    }
}
