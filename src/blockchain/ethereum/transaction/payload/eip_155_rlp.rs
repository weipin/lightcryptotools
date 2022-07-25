// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::eip_155::PayloadEip155;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::tools::codable::{Encodable, EncodingItem};

// ...when computing the hash of a transaction for the purposes of signing,
// ...you SHOULD hash nine rlp encoded elements
// (nonce, gasprice, startgas, to, value, data, chainid, 0, 0)...
//
// See EIP-155: Simple replay attack protection
// https://eips.ethereum.org/EIPS/eip-155
impl Encodable<RlpEncodingItem> for PayloadEip155 {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut list_encoding_item = RlpEncodingItem::new();
        self.nonce.encode_to(&mut list_encoding_item);
        self.gas_price.encode_to(&mut list_encoding_item);
        self.gas_limit.encode_to(&mut list_encoding_item);
        self.destination.encode_to(&mut list_encoding_item);
        self.amount.encode_to(&mut list_encoding_item);
        self.data.encode_to(&mut list_encoding_item);
        self.chain_id.encode_to(&mut list_encoding_item);
        0_u64.encode_to(&mut list_encoding_item);
        0_u64.encode_to(&mut list_encoding_item);

        encoding_item.encode_list_payload(&mut list_encoding_item);
    }
}
