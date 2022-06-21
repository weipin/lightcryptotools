// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::access_list::{AccessList, AccessListItem};
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::tools::codable::{Encodable, EncodingItem};

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

impl Encodable<RlpEncodingItem> for AccessList {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut list_encoding_item = RlpEncodingItem::new(); // items container

        for item in &self.0 {
            item.encode_to(&mut list_encoding_item);
        }

        encoding_item.encode_list_payload(&mut list_encoding_item);
    }
}
