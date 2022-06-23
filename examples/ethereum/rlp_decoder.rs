// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Decodes RLP and prints the decoded structure.
//!
//! - For convenience, we leverage `serde_json` (for its data storage and pretty printing)
//!   to represent the decoded RLP structure.
//! - RLP "single items" are interpreted as they are -- the "raw bytes".
//! - These "raw bytes" items are represented as JSON strings in hex format.
//! - For the CLI hex input parameter, the prefix '0x' is optional.
//!
//! # Examples
//!
//! ```
//! # The hex input is from https://eips.ethereum.org/EIPS/eip-155
//! cargo run --example rlp_decoder -- 0xec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080
//!
//! # Decodes RLP for `[ [], [[]], [ [], [[]] ] ]`, prefix "0x" omitted.
//! # It's an example from https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
//! cargo run --example rlp_decoder -- c7c0c1c0c3c0c1c0
//! ```

use lightcryptotools::blockchain::ethereum::rlp::decoder::RlpDecodingItem;
use lightcryptotools::blockchain::ethereum::rlp::decoding::RlpDataDecodingError;
use lightcryptotools::blockchain::ethereum::rlp::RlpItemType;
use lightcryptotools::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
use lightcryptotools::tools::codable::{decode, Decodable, DecodingItem};
use serde_json::{to_string_pretty, Value};
use std::borrow::Cow;

fn main() {
    let rlp_hex = std::env::args()
        .nth(1)
        .expect("Error: the parameter is missing");

    let rlp_hex: Cow<str> = if let Some(hex) = rlp_hex.strip_prefix("0x") {
        hex.into()
    } else {
        rlp_hex.into()
    };

    let rlp_data = match hex_to_bytes(rlp_hex.as_ref()) {
        Ok(data) => data,
        Err(err) => {
            println!("invalid hex input: {err}");
            return;
        }
    };
    let json_value_wrapper: JsonValueWrapper = match decode(&rlp_data) {
        Ok(value) => value,
        Err(err) => {
            println!("Decoding failed: {err}");
            return;
        }
    };
    println!("{}", to_string_pretty(&json_value_wrapper.0).unwrap());
}

struct JsonValueWrapper(Value);

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for JsonValueWrapper {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        return match decoding_item.item_type {
            RlpItemType::SingleValue => match decoding_item.decode_as_bytes() {
                Ok(bytes) => Ok(JsonValueWrapper(Value::String(
                    "0x".to_owned() + &bytes_to_lower_hex(bytes),
                ))),
                Err(err) => Err(err),
            },
            RlpItemType::List => match decoding_item.decode_as_items() {
                Ok(items) => {
                    let mut values = Vec::with_capacity(items.len());
                    for item in items {
                        match Self::decode_from(&item) {
                            Ok(value) => {
                                values.push(value.0);
                            }
                            Err(err) => {
                                return Err(err);
                            }
                        }
                    }
                    Ok(JsonValueWrapper(Value::Array(values)))
                }
                Err(err) => Err(err),
            },
        };
    }
}
