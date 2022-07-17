// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::access_list::{AccessList, AccessListItem};
use crate::blockchain::ethereum::rlp::decoder::RlpDecodingItem;
use crate::blockchain::ethereum::rlp::decoding::RlpDataDecodingError;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::blockchain::ethereum::rlp::RlpItemType;
use crate::blockchain::ethereum::types::{Address, StorageKey};
use crate::tools::codable::{Decodable, DecodingItem, Encodable, EncodingItem};

impl Encodable<RlpEncodingItem> for AccessListItem {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut item_encoding_item = RlpEncodingItem::new(); // item container
        self.address.encode_to(&mut item_encoding_item); // address -> item container
        self.storage_keys.encode_to(&mut item_encoding_item);

        encoding_item.encode_list_payload(&mut item_encoding_item);
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for AccessListItem {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        return match decoding_item.item_type {
            RlpItemType::SingleValue => Err(RlpDataDecodingError::InvalidFormat),
            RlpItemType::List => {
                let items = decoding_item.decode_as_items()?;
                if items.len() != 2 {
                    return Err(RlpDataDecodingError::InvalidFormat);
                }
                let mut iter = items.iter();

                let address = Address::decode_from(iter.next().unwrap())?;
                let storage_keys = Vec::<StorageKey>::decode_from(iter.next().unwrap())?;
                Ok(AccessListItem {
                    address,
                    storage_keys,
                })
            }
        };
    }
}

impl Encodable<RlpEncodingItem> for AccessList {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        self.0.encode_to(encoding_item);
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for AccessList {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        return match decoding_item.item_type {
            RlpItemType::SingleValue => Err(RlpDataDecodingError::InvalidFormat),
            RlpItemType::List => {
                let access_list_items = Vec::<AccessListItem>::decode_from(decoding_item)?;
                Ok(AccessList(access_list_items))
            }
        };
    }
}
