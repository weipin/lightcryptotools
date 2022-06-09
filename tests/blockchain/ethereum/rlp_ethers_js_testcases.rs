// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! To test against the data provided in the JSON file "rlp-coder.json,"
//! this file implements the `Encodable` and `Decodable` for `JsonObject`,
//! which is a newtype around `serde_json::Value`.
//!
//! Note:
//! rlp-coder.json contains only types "string" and "array".
//! All the "strings" are lowercase hex representing bytes, and it eliminates the
//! type ambiguity of the "single value" decoding target.

use devtools::path::integration_testing_data_path;
use lightcryptotools::blockchain::ethereum::rlp::decoder::RlpDecodingItem;
use lightcryptotools::blockchain::ethereum::rlp::decoding::RlpDataDecodingError;
use lightcryptotools::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use lightcryptotools::blockchain::ethereum::rlp::RlpItemType;
use lightcryptotools::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
use lightcryptotools::tools::codable::{
    decode, encode, Decodable, DecodingItem, Encodable, EncodingItem,
};
use serde_json::Value;
use std::fs::File;

#[test]
fn test_encoding() {
    let path = integration_testing_data_path("blockchain/ethereum/ethers.js/rlp-coder.json");
    let file = File::open(path).unwrap();
    let value_vec: Vec<Value> = serde_json::from_reader(file).unwrap();

    let mut count = 0;
    for mut value in value_vec {
        let decoded_value = value["decoded"].take();
        let encoded_hex = value["encoded"]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap();

        let encoded = encode(&JsonValue(decoded_value));
        assert_eq!(bytes_to_lower_hex(&encoded), encoded_hex);
        count += 1;
    }
    assert!(count > 60);
}

#[test]
fn test_decoding() {
    let path = integration_testing_data_path("blockchain/ethereum/ethers.js/rlp-coder.json");
    let file = File::open(path).unwrap();
    let value_vec: Vec<Value> = serde_json::from_reader(file).unwrap();

    let mut count = 0;
    for mut value in value_vec {
        let decoded_value = value["decoded"].take();
        let encoded_hex = value["encoded"]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap();

        let json_value: JsonValue = decode(&hex_to_bytes(encoded_hex).unwrap()).unwrap();
        assert_eq!(json_value.0, decoded_value);
        count += 1;
    }
    assert!(count > 60);
}

struct JsonValue(Value);

impl Encodable<RlpEncodingItem> for JsonValue {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        encode_json_value(&self.0, encoding_item);
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for JsonValue {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        match decode_json_value(decoding_item) {
            Ok(value) => Ok(JsonValue(value)),
            Err(err) => Err(err),
        }
    }
}

fn encode_json_value(value: &Value, encoding_item: &mut RlpEncodingItem) {
    match value {
        Value::Null => {
            unimplemented!();
        }
        Value::Bool(_) => {
            unimplemented!();
        }
        Value::Number(_) => {
            unimplemented!();
        }
        Value::String(s) => {
            let bytes = hex_to_bytes(s.strip_prefix("0x").unwrap()).unwrap();
            encoding_item.encode_bytes(&bytes);
        }
        Value::Array(values) => {
            let mut values_encoding_item = RlpEncodingItem::new();
            for value in values {
                encode_json_value(value, &mut values_encoding_item);
            }
            encoding_item.encode_list_payload(&mut values_encoding_item);
        }
        Value::Object(_) => {
            unimplemented!();
        }
    }
}

fn decode_json_value(decoding_item: &RlpDecodingItem) -> Result<Value, RlpDataDecodingError> {
    return match decoding_item.item_type {
        RlpItemType::SingleValue => match decoding_item.decode_as_bytes() {
            Ok(s) => {
                let hex = bytes_to_lower_hex(s);
                Ok(Value::String(format!("0x{hex}")))
            }
            Err(err) => Err(err),
        },
        RlpItemType::List => match decoding_item.decode_as_items() {
            Ok(items) => {
                let mut values = Vec::with_capacity(items.len());
                for item in items {
                    match decode_json_value(&item) {
                        Ok(value) => {
                            values.push(value);
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    }
                }
                Ok(Value::Array(values))
            }
            Err(err) => Err(err),
        },
    };
}
