// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides `EncodingItem` implementation for RLP.

use super::core::RlpItemType;
use super::encoding::{encode_payload_length, encode_single_value};
use crate::tools::bytes::strip_leading_zeros;
use crate::tools::codable::EncodingItem;

/// The RLP encoding type which implements `EncodingItem`.
pub struct RlpEncodingItem {
    encoded_data: Vec<u8>,
}

impl EncodingItem for RlpEncodingItem {
    fn new() -> RlpEncodingItem {
        RlpEncodingItem {
            encoded_data: vec![],
        }
    }

    fn encode_u64(&mut self, n: u64) {
        self.encoded_data
            .append(&mut encode_single_value(strip_leading_zeros(
                &n.to_be_bytes(),
            )));
    }

    fn encode_str(&mut self, s: &str) {
        self.encoded_data
            .append(&mut encode_single_value(s.as_bytes()));
    }

    fn encode_bytes(&mut self, bytes: &[u8]) {
        self.encoded_data.append(&mut encode_single_value(bytes));
    }

    fn encode_list_payload(&mut self, item: &mut RlpEncodingItem) {
        let mut header = encode_payload_length(RlpItemType::List, &item.encoded_data);
        self.encoded_data.append(&mut header);
        self.encoded_data.append(&mut item.encoded_data);
    }

    fn take_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.encoded_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::hex_to_bytes;
    use crate::tools::codable::{encode, Encodable};
    use devtools::path::integration_testing_data_path;
    use serde_json::Value;
    use std::fs::File;

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
                    encoding_item.encode_u64(n);
                }
                Value::String(s) => {
                    encoding_item.encode_str(&s);
                }
                Value::Array(values) => {
                    let mut values_encoding_item = RlpEncodingItem::new();
                    for value in values {
                        value.encode_to(&mut values_encoding_item);
                    }
                    encoding_item.encode_list_payload(&mut values_encoding_item);
                }
                Value::Object(_) => {
                    unimplemented!();
                }
            }
        }
    }
}
