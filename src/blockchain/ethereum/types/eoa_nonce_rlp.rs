// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::eoa_nonce::EoaNonce;
use crate::blockchain::ethereum::rlp::decoder::RlpDecodingItem;
use crate::blockchain::ethereum::rlp::decoding::RlpDataDecodingError;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::tools::codable::{Decodable, DecodingItem, Encodable, EncodingItem};

impl Encodable<RlpEncodingItem> for EoaNonce {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        encoding_item.encode_u64(self.value());
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for EoaNonce {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        let n = decoding_item.decode_as_u64()?;
        let nonce = n
            .try_into()
            .map_err(|_| RlpDataDecodingError::InvalidFormat)?;
        Ok(nonce)
    }
}
