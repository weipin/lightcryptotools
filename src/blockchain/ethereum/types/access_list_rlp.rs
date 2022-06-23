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

        // storage keys container
        let mut storage_keys_encoding_item = RlpEncodingItem::new();
        for key in &self.storage_keys {
            key.encode_to(&mut storage_keys_encoding_item); // key -> storage keys container
        }
        // storage keys => item container
        item_encoding_item.encode_list_payload(&mut storage_keys_encoding_item);

        encoding_item.encode_list_payload(&mut item_encoding_item);
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for AccessListItem {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        return match decoding_item.item_type {
            RlpItemType::SingleValue => Err(RlpDataDecodingError::InvalidFormat),
            RlpItemType::List => match decoding_item.decode_as_items() {
                Ok(items) => {
                    if items.len() != 2 {
                        return Err(RlpDataDecodingError::InvalidFormat);
                    }
                    let mut iter = items.iter();

                    let address = Address::decode_from(iter.next().unwrap())?;
                    let storage_keys_decoding_items = iter.next().unwrap().decode_as_items()?;
                    let mut storage_keys =
                        Vec::with_capacity(storage_keys_decoding_items.len());
                    for item in storage_keys_decoding_items {
                        let storage_key = StorageKey::decode_from(&item)?;
                        storage_keys.push(storage_key);
                    }
                    Ok(AccessListItem {
                        address,
                        storage_keys,
                    })
                }
                Err(err) => Err(err),
            },
        };
    }
}

impl Encodable<RlpEncodingItem> for AccessList {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut list_encoding_item = RlpEncodingItem::new(); // items container

        for item in &self.0 {
            item.encode_to(&mut list_encoding_item);
        }

        encoding_item.encode_list_payload(&mut list_encoding_item);
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for AccessList {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        return match decoding_item.item_type {
            RlpItemType::SingleValue => Err(RlpDataDecodingError::InvalidFormat),
            RlpItemType::List => match decoding_item.decode_as_items() {
                Ok(items) => {
                    let mut access_list_items = Vec::with_capacity(items.len());
                    for item in items {
                        let access_list_item = AccessListItem::decode_from(&item)?;
                        access_list_items.push(access_list_item);
                    }
                    Ok(AccessList(access_list_items))
                }
                Err(err) => Err(err),
            },
        };
    }
}
