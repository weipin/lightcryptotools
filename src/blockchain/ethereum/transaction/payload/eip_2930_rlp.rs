// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::eip_2930::PayloadEip2930;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::tools::codable::{Encodable, EncodingItem};

// [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList]
// See EIP-2930: https://eips.ethereum.org/EIPS/eip-2930
impl Encodable<RlpEncodingItem> for PayloadEip2930 {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut list_encoding_item = RlpEncodingItem::new();

        self.chain_id.encode_to(&mut list_encoding_item);
        self.nonce.encode_to(&mut list_encoding_item);
        self.gas_price.encode_to(&mut list_encoding_item);
        list_encoding_item.encode_u64(self.gas_limit);
        self.destination.encode_to(&mut list_encoding_item);
        self.amount.encode_to(&mut list_encoding_item);
        list_encoding_item.encode_bytes(&self.data);
        self.access_list.encode_to(&mut list_encoding_item);

        encoding_item.encode_list_payload(&mut list_encoding_item);
    }
}
