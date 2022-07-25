// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::blockchain::ethereum::rlp::decoder::RlpDecodingItem;
use crate::blockchain::ethereum::rlp::decoding::RlpDataDecodingError;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::blockchain::ethereum::rlp::RlpItemType;
use crate::blockchain::ethereum::types::address::Address;
use crate::tools::codable::{Decodable, Encodable};

impl Encodable<RlpEncodingItem> for Address {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        encoding_item.encode_bytes(&self.0);
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for Address {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        match decoding_item.item_type {
            RlpItemType::SingleValue => {
                let bytes = decoding_item.decode_as_bytes()?;
                if let Some(address) = Address::from_bytes(bytes) {
                    Ok(address)
                } else {
                    Err(RlpDataDecodingError::InvalidFormat)
                }
            }
            RlpItemType::List => Err(RlpDataDecodingError::InvalidFormat),
        }
    }
}
