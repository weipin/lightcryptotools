// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides `DecodingItem` implementation for RLP.

use super::core::RlpItemType;
use super::decoding::{decode_data, decode_list_payload, RlpDataDecodingError};
use crate::bigint::BigUint;
use crate::tools::codable::{Decodable, DecodingItem};

/// The RLP decoding type which implements `DecodingItem`.
pub struct RlpDecodingItem<'a> {
    pub item_type: RlpItemType,
    payload: &'a [u8],
}

impl<'a> RlpDecodingItem<'a> {
    pub fn decode_as_bytes(&self) -> Result<&[u8], RlpDataDecodingError> {
        if self.item_type != RlpItemType::SingleValue {
            return Err(RlpDataDecodingError::InvalidFormat);
        }
        Ok(self.payload)
    }

    pub fn decode_as_items(&self) -> Result<Vec<Self>, RlpDataDecodingError> {
        if self.item_type != RlpItemType::List {
            return Err(RlpDataDecodingError::InvalidFormat);
        }

        let items = decode_list_payload(self.payload)?;
        let mut decoding_items = Vec::with_capacity(items.len());
        for (item_type, payload) in items {
            decoding_items.push(RlpDecodingItem { item_type, payload });
        }

        Ok(decoding_items)
    }
}

impl<'a> DecodingItem<'a> for RlpDecodingItem<'a> {
    type Error = RlpDataDecodingError;

    fn new_from_data(data: &'a [u8]) -> Result<Self, Self::Error> {
        let (item_type, payload) = decode_data(data)?;
        Ok(RlpDecodingItem { item_type, payload })
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for u64 {
    fn decode_from(decoding_item: &RlpDecodingItem<'a>) -> Result<Self, RlpDataDecodingError> {
        if decoding_item.item_type != RlpItemType::SingleValue {
            return Err(RlpDataDecodingError::InvalidFormat);
        }

        if decoding_item.payload.len() > std::mem::size_of::<u64>() {
            return Err(RlpDataDecodingError::InvalidFormat);
        }

        let mut n_bytes = [0; std::mem::size_of::<u64>()];
        n_bytes[(std::mem::size_of::<u64>() - decoding_item.payload.len())..]
            .copy_from_slice(decoding_item.payload);
        let n = u64::from_be_bytes(n_bytes);

        Ok(n)
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for String {
    fn decode_from(decoding_item: &RlpDecodingItem<'a>) -> Result<Self, RlpDataDecodingError> {
        if decoding_item.item_type != RlpItemType::SingleValue {
            return Err(RlpDataDecodingError::InvalidFormat);
        }

        match String::from_utf8(decoding_item.payload.to_vec()) {
            Ok(str) => Ok(str),
            Err(_) => Err(RlpDataDecodingError::InvalidFormat),
        }
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for Vec<u8> {
    fn decode_from(decoding_item: &RlpDecodingItem<'a>) -> Result<Self, RlpDataDecodingError> {
        if decoding_item.item_type != RlpItemType::SingleValue {
            return Err(RlpDataDecodingError::InvalidFormat);
        }

        Ok(decoding_item.payload.to_vec())
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for BigUint {
    fn decode_from(decoding_item: &RlpDecodingItem<'a>) -> Result<Self, RlpDataDecodingError> {
        if decoding_item.item_type != RlpItemType::SingleValue {
            return Err(RlpDataDecodingError::InvalidFormat);
        }

        Ok(if decoding_item.payload.is_empty() {
            // BigInt represents 0 as [0_u8] -- empty is not allowed.
            BigUint::from_be_bytes(&[0])
        } else {
            BigUint::from_be_bytes(decoding_item.payload)
        })
    }
}

/// Makes `Vec<T>` RLP decodable. The element type `T` must be RLP decodable.
impl<'a, T> Decodable<'a, RlpDecodingItem<'a>> for Vec<T>
where
    T: Decodable<'a, RlpDecodingItem<'a>>,
{
    fn decode_from(decoding_item: &RlpDecodingItem<'a>) -> Result<Self, RlpDataDecodingError> {
        debug_assert!(decoding_item.item_type == RlpItemType::List);

        let items = decoding_item.decode_as_items()?;
        let mut values = Self::with_capacity(items.len());
        for item in items {
            let value = T::decode_from(&item)?;
            values.push(value);
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::hex_to_bytes;
    use crate::tools::codable::{decode, Decodable};
    use devtools::path::integration_testing_data_path;
    use serde_json::{Number, Value};
    use std::fs::File;

    #[test]
    fn test_decoding_u64() {
        // decode_as_u64, length == 0
        let decoding_item = RlpDecodingItem {
            item_type: RlpItemType::SingleValue,
            payload: &[],
        };
        assert_eq!(u64::decode_from(&decoding_item).unwrap(), 0);
    }

    #[test]
    fn test_decoding_error_cases() {
        // decode_as_u64, length > 8
        let decoding_item = RlpDecodingItem {
            item_type: RlpItemType::SingleValue,
            payload: &[1, 2, 3, 4, 5, 6, 7, 8, 9],
        };
        assert!(u64::decode_from(&decoding_item).is_err());
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

            // Decodes a `serde_json::Value` from `output`.
            // See `Decodable` implementations for `JsonValueSingleValueU64` and `JsonValueSingleValueString`.
            //
            // Both implementations are identical except the decoding part of the "single value item":
            // to `u64` for `JsonValueSingleValueU64` and to `String` for `JsonValueSingleValueString`.
            //
            // Providing these two implementations is necessary to remove the ambiguity
            // because `output` doesn't contain any type information of "single value item."
            //
            // Also, an extra field "mode" was added to the JSON testing data.
            // The testing code below uses this field to determine the target type of the "single value item."
            let value = match value["mode"].as_str() {
                None => {
                    let value: JsonValueSingleValueString = decode(&output).unwrap();
                    value.0
                }
                Some(s) => match s {
                    "string" => {
                        let value: JsonValueSingleValueString = decode(&output).unwrap();
                        value.0
                    }
                    "int" => {
                        let value: JsonValueSingleValueU64 = decode(&output).unwrap();
                        value.0
                    }
                    _ => {
                        panic!("invalid type")
                    }
                },
            };

            assert_eq!(&value, input);
        }
    }

    struct JsonValueSingleValueU64(Value);

    impl<'a> Decodable<'a, RlpDecodingItem<'a>> for JsonValueSingleValueU64 {
        fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
            return match decoding_item.item_type {
                RlpItemType::SingleValue => {
                    let n = u64::decode_from(decoding_item)?;
                    Ok(Self(Value::Number(Number::from(n))))
                }
                RlpItemType::List => {
                    let values = Vec::<Self>::decode_from(decoding_item)?;
                    Ok(Self(Value::Array(
                        values.into_iter().map(|t| t.0).collect(),
                    )))
                }
            };
        }
    }

    struct JsonValueSingleValueString(Value);

    impl<'a> Decodable<'a, RlpDecodingItem<'a>> for JsonValueSingleValueString {
        fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
            return match decoding_item.item_type {
                RlpItemType::SingleValue => {
                    let s = String::decode_from(decoding_item)?;
                    Ok(Self(Value::String(s.into())))
                }
                RlpItemType::List => {
                    let values = Vec::<Self>::decode_from(decoding_item)?;
                    Ok(Self(Value::Array(
                        values.into_iter().map(|t| t.0).collect(),
                    )))
                }
            };
        }
    }
}
