// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::eip_1559::PayloadEip1559;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::tools::codable::{Encodable, EncodingItem};

// [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list]
// See EIP-1559: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md
impl Encodable<RlpEncodingItem> for PayloadEip1559 {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut list_encoding_item = RlpEncodingItem::new();

        self.chain_id.encode_to(&mut list_encoding_item);
        self.nonce.encode_to(&mut list_encoding_item);
        self.max_priority_fee_per_gas
            .encode_to(&mut list_encoding_item);
        self.max_fee_per_gas.encode_to(&mut list_encoding_item);
        self.gas_limit.encode_to(&mut list_encoding_item);
        self.destination.encode_to(&mut list_encoding_item);
        self.amount.encode_to(&mut list_encoding_item);
        self.data.encode_to(&mut list_encoding_item);
        self.access_list.encode_to(&mut list_encoding_item);

        encoding_item.encode_list_payload(&mut list_encoding_item);
    }
}
