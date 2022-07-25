// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::transaction_eip_155::TransactionEip155;
use crate::bigint::BigUint;
use crate::blockchain::ethereum::rlp::decoder::RlpDecodingItem;
use crate::blockchain::ethereum::rlp::decoding::RlpDataDecodingError;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::blockchain::ethereum::rlp::RlpItemType;
use crate::blockchain::ethereum::transaction::TransactionBuilder;
use crate::blockchain::ethereum::types::{Address, EoaNonce, Wei};
use crate::tools::codable::{Decodable, Encodable, EncodingItem};

impl Encodable<RlpEncodingItem> for TransactionEip155 {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut list_encoding_item = RlpEncodingItem::new();
        self.payload.nonce.encode_to(&mut list_encoding_item);
        self.payload.gas_price.encode_to(&mut list_encoding_item);
        self.payload.gas_limit.encode_to(&mut list_encoding_item);
        self.payload.destination.encode_to(&mut list_encoding_item);
        self.payload.amount.encode_to(&mut list_encoding_item);
        self.payload.data.encode_to(&mut list_encoding_item);
        self.v.encode_to(&mut list_encoding_item);
        self.r.encode_to(&mut list_encoding_item);
        self.s.encode_to(&mut list_encoding_item);

        encoding_item.encode_list_payload(&mut list_encoding_item);
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for TransactionEip155 {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        return match decoding_item.item_type {
            RlpItemType::SingleValue => Err(RlpDataDecodingError::InvalidFormat),
            RlpItemType::List => {
                let items = decoding_item.decode_as_items()?;
                if items.len() != 9 {
                    return Err(RlpDataDecodingError::InvalidFormat);
                }
                let mut iter = items.iter();

                let nonce = EoaNonce::decode_from(iter.next().unwrap())?;
                let gas_price = Wei::decode_from(iter.next().unwrap())?;
                let gas_limit = u64::decode_from(iter.next().unwrap())?;
                let destination = Address::decode_from(iter.next().unwrap())?;
                let amount = Wei::decode_from(iter.next().unwrap())?;
                let data = Vec::<u8>::decode_from(iter.next().unwrap())?;
                let v = BigUint::decode_from(iter.next().unwrap())?;
                let r = BigUint::decode_from(iter.next().unwrap())?;
                let s = BigUint::decode_from(iter.next().unwrap())?;

                // The v of EIP-155 is greater or equal to 35 (>=35):
                // `v = CHAIN_ID * 2 + 35 or v = CHAIN_ID * 2 + 36`
                // Otherwise, the transaction is a legacy type: v is 27 or 28.
                let n_35 = BigUint::from(35_u8);
                if v < n_35 {
                    return Err(RlpDataDecodingError::TransactionTypeMismatch);
                }
                let chain_id_n = (&v - n_35) >> 2;

                let payload = TransactionBuilder::new()
                    .with_chain_id(chain_id_n.into())
                    .with_nonce(nonce)
                    .with_gas_price(gas_price)
                    .with_gas_limit(gas_limit)
                    .with_destination(destination)
                    .with_amount(amount)
                    .with_data(data)
                    .take_and_build_payload_eip_155()
                    .map_err(|_| RlpDataDecodingError::InvalidFormat)?;

                Ok(TransactionEip155 { payload, v, r, s })
            }
        };
    }
}
