// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides `EncodingItem` implementation for RLP.

use super::core::RlpItemType;
use super::encoding::{encode_payload_length, encode_single_value};
use crate::bigint::BigUint;
use crate::tools::bytes::strip_leading_zeros;
use crate::tools::codable::{Encodable, EncodingItem};

/// The RLP encoding type which implements `EncodingItem`.
pub struct RlpEncodingItem {
    encoded_data: Vec<u8>,
}

impl RlpEncodingItem {
    fn extend_encoded_data(&mut self, bytes: &[u8]) {
        self.encoded_data.extend(bytes);
    }

    pub fn encode_bytes(&mut self, bytes: &[u8]) {
        self.extend_encoded_data(&encode_single_value(bytes));
    }

    pub fn encode_list_payload(&mut self, item: &mut RlpEncodingItem) {
        let header = encode_payload_length(RlpItemType::List, &item.encoded_data);
        self.extend_encoded_data(&header);
        self.extend_encoded_data(&item.encoded_data);
    }
}

impl EncodingItem for RlpEncodingItem {
    fn new() -> RlpEncodingItem {
        RlpEncodingItem {
            encoded_data: vec![],
        }
    }

    fn take_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.encoded_data)
    }
}

impl Encodable<RlpEncodingItem> for u64 {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        encoding_item.extend_encoded_data(&encode_single_value(strip_leading_zeros(
            &self.to_be_bytes(),
        )));
    }
}

impl Encodable<RlpEncodingItem> for BigUint {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        encoding_item.extend_encoded_data(&encode_single_value(strip_leading_zeros(
            &self.to_be_bytes(),
        )));
    }
}

impl Encodable<RlpEncodingItem> for &str {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        encoding_item.extend_encoded_data(&encode_single_value(self.as_bytes()));
    }
}

/// Makes `Vec<T>` RLP encodable. The element type `T` must be RLP encodable.
impl<T> Encodable<RlpEncodingItem> for Vec<T>
where
    T: Encodable<RlpEncodingItem>,
{
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut values_encoding_item = RlpEncodingItem::new();
        for value in self {
            value.encode_to(&mut values_encoding_item);
        }
        encoding_item.encode_list_payload(&mut values_encoding_item);
    }
}

impl Encodable<RlpEncodingItem> for Vec<u8> {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        encoding_item.encode_bytes(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
    use crate::tools::codable::{encode, Encodable};
    use devtools::path::integration_testing_data_path;
    use serde_json::Value;
    use std::fs::File;

    #[test]
    fn test_take_data_emptying_internal_data() {
        let mut encoding_item = RlpEncodingItem::new();
        12_u64.encode_to(&mut encoding_item);
        assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), "0c");

        // Reuses `encoding_item`
        19_u64.encode_to(&mut encoding_item);
        assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), "13");
    }

    #[test]
    fn test_examples() {
        let path = integration_testing_data_path("blockchain/ethereum/rlp_spec_samples.json");
        let file = File::open(path).unwrap();
        let value_vec: Vec<Value> = serde_json::from_reader(file).unwrap();

        for value in value_vec {
            let input = &value["in"];
            let output_hex = value["out"].as_str().unwrap();
            let output = hex_to_bytes(output_hex).unwrap();

            // Encodes a `serde_json::Value`.
            // See the `Encodable` implementation for `serde_json::Value` below.
            let bytes = encode(input);
            assert_eq!(bytes, output);
        }
    }

    impl Encodable<RlpEncodingItem> for Value {
        fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
            match self {
                Value::Null => {
                    unimplemented!();
                }
                Value::Bool(_) => {
                    unimplemented!();
                }
                Value::Number(number) => {
                    let n = number.as_u64().unwrap();
                    n.encode_to(encoding_item);
                }
                Value::String(s) => {
                    s.as_str().encode_to(encoding_item);
                }
                Value::Array(values) => {
                    values.encode_to(encoding_item);
                }
                Value::Object(_) => {
                    unimplemented!();
                }
            }
        }
    }
}
