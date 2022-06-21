// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::transaction_eip_1559::TransactionEip1559;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::tools::codable::{Encodable, EncodingItem};

impl Encodable<RlpEncodingItem> for TransactionEip1559 {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut list_encoding_item = RlpEncodingItem::new();

        self.payload.chain_id.encode_to(&mut list_encoding_item);
        self.payload.nonce.encode_to(&mut list_encoding_item);
        self.payload
            .max_priority_fee_per_gas
            .encode_to(&mut list_encoding_item);
        self.payload
            .max_fee_per_gas
            .encode_to(&mut list_encoding_item);
        list_encoding_item.encode_u64(self.payload.gas_limit);
        self.payload.destination.encode_to(&mut list_encoding_item);
        self.payload.amount.encode_to(&mut list_encoding_item);
        list_encoding_item.encode_bytes(&self.payload.data);
        self.payload.access_list.encode_to(&mut list_encoding_item);
        list_encoding_item.encode_u64(self.y_parity as u64);
        list_encoding_item.encode_biguint(&self.r);
        list_encoding_item.encode_biguint(&self.s);

        encoding_item.encode_list_payload(&mut list_encoding_item);
    }
}
