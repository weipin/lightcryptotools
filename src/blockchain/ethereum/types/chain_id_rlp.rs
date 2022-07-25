// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigUint;
use crate::blockchain::ethereum::rlp::decoder::RlpDecodingItem;
use crate::blockchain::ethereum::rlp::decoding::RlpDataDecodingError;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::blockchain::ethereum::types::ChainId;
use crate::tools::codable::{Decodable, Encodable};

impl Encodable<RlpEncodingItem> for ChainId {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        self.0.encode_to(encoding_item);
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for ChainId {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        let n = BigUint::decode_from(decoding_item)?;
        Ok(ChainId(n))
    }
}
