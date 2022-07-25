// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::legacy::PayloadLegacy;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::tools::codable::{Encodable, EncodingItem};

impl Encodable<RlpEncodingItem> for PayloadLegacy {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut list_encoding_item = RlpEncodingItem::new();
        self.nonce.encode_to(&mut list_encoding_item);
        self.gas_price.encode_to(&mut list_encoding_item);
        self.gas_limit.encode_to(&mut list_encoding_item);
        self.destination.encode_to(&mut list_encoding_item);
        self.amount.encode_to(&mut list_encoding_item);
        self.data.encode_to(&mut list_encoding_item);

        encoding_item.encode_list_payload(&mut list_encoding_item);
    }
}
