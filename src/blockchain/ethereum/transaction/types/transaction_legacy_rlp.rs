// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::transaction_legacy::TransactionLegacy;
use crate::bigint::BigUint;
use crate::blockchain::ethereum::rlp::decoder::RlpDecodingItem;
use crate::blockchain::ethereum::rlp::decoding::RlpDataDecodingError;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::blockchain::ethereum::rlp::RlpItemType;
use crate::blockchain::ethereum::transaction::TransactionBuilder;
use crate::blockchain::ethereum::types::{Address, EoaNonce, Wei};
use crate::tools::codable::{Decodable, Encodable, EncodingItem};

impl Encodable<RlpEncodingItem> for TransactionLegacy {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut list_encoding_item = RlpEncodingItem::new();
        self.payload.nonce.encode_to(&mut list_encoding_item);
        self.payload.gas_price.encode_to(&mut list_encoding_item);
        self.payload.gas_limit.encode_to(&mut list_encoding_item);
        self.payload.destination.encode_to(&mut list_encoding_item);
        self.payload.amount.encode_to(&mut list_encoding_item);
        self.payload.data.encode_to(&mut list_encoding_item);
        (self.v as u64).encode_to(&mut list_encoding_item);
        self.r.encode_to(&mut list_encoding_item);
        self.s.encode_to(&mut list_encoding_item);

        encoding_item.encode_list_payload(&mut list_encoding_item);
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for TransactionLegacy {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        return match decoding_item.item_type {
            RlpItemType::SingleValue => Err(RlpDataDecodingError::InvalidFormat),
            RlpItemType::List => {
                let items = decoding_item.decode_as_items()?;
                if items.len() != 9 {
                    return Err(RlpDataDecodingError::InvalidFormat);
                }
                let mut iter = items.iter();

                let payload = TransactionBuilder::new()
                    .with_nonce(EoaNonce::decode_from(iter.next().unwrap())?)
                    .with_gas_price(Wei::decode_from(iter.next().unwrap())?)
                    .with_gas_limit(u64::decode_from(iter.next().unwrap())?)
                    .with_destination(Address::decode_from(iter.next().unwrap())?)
                    .with_amount(Wei::decode_from(iter.next().unwrap())?)
                    .with_data(Vec::<u8>::decode_from(iter.next().unwrap())?)
                    .take_and_build_payload_legacy()
                    .map_err(|_| RlpDataDecodingError::InvalidFormat)?;

                let v_u64 = u64::decode_from(iter.next().unwrap())?;
                let v = u8::try_from(v_u64).map_err(|_| RlpDataDecodingError::InvalidFormat)?;
                let r = BigUint::decode_from(iter.next().unwrap())?;
                let s = BigUint::decode_from(iter.next().unwrap())?;

                Ok(TransactionLegacy { payload, v, r, s })
            }
        };
    }
}
