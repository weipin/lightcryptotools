// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::transaction_eip_2930::TransactionEip2930;
use crate::bigint::BigUint;
use crate::blockchain::ethereum::rlp::decoder::RlpDecodingItem;
use crate::blockchain::ethereum::rlp::decoding::RlpDataDecodingError;
use crate::blockchain::ethereum::rlp::encoder::RlpEncodingItem;
use crate::blockchain::ethereum::rlp::RlpItemType;
use crate::blockchain::ethereum::transaction::TransactionBuilder;
use crate::blockchain::ethereum::types::{AccessList, Address, ChainId, EoaNonce, Wei};
use crate::crypto::ecdsa::ecdsa_core::YParity;
use crate::tools::codable::{Decodable, Encodable, EncodingItem};

impl Encodable<RlpEncodingItem> for TransactionEip2930 {
    fn encode_to(&self, encoding_item: &mut RlpEncodingItem) {
        let mut list_encoding_item = RlpEncodingItem::new();

        self.payload.chain_id.encode_to(&mut list_encoding_item);
        self.payload.nonce.encode_to(&mut list_encoding_item);
        self.payload.gas_price.encode_to(&mut list_encoding_item);
        self.payload.gas_limit.encode_to(&mut list_encoding_item);
        self.payload.destination.encode_to(&mut list_encoding_item);
        self.payload.amount.encode_to(&mut list_encoding_item);
        self.payload.data.encode_to(&mut list_encoding_item);
        self.payload.access_list.encode_to(&mut list_encoding_item);
        (self.y_parity as u64).encode_to(&mut list_encoding_item);
        self.r.encode_to(&mut list_encoding_item);
        self.s.encode_to(&mut list_encoding_item);

        encoding_item.encode_list_payload(&mut list_encoding_item);
    }
}

impl<'a> Decodable<'a, RlpDecodingItem<'a>> for TransactionEip2930 {
    fn decode_from(decoding_item: &RlpDecodingItem) -> Result<Self, RlpDataDecodingError> {
        return match decoding_item.item_type {
            RlpItemType::SingleValue => Err(RlpDataDecodingError::InvalidFormat),
            RlpItemType::List => {
                let items = decoding_item.decode_as_items()?;
                if items.len() != 11 {
                    return Err(RlpDataDecodingError::InvalidFormat);
                }
                let mut iter = items.iter();

                let payload = TransactionBuilder::new()
                    .with_chain_id(ChainId::decode_from(iter.next().unwrap())?)
                    .with_nonce(EoaNonce::decode_from(iter.next().unwrap())?)
                    .with_gas_price(Wei::decode_from(iter.next().unwrap())?)
                    .with_gas_limit(u64::decode_from(iter.next().unwrap())?)
                    .with_destination(Address::decode_from(iter.next().unwrap())?)
                    .with_amount(Wei::decode_from(iter.next().unwrap())?)
                    .with_data(Vec::<u8>::decode_from(iter.next().unwrap())?)
                    .with_access_list(AccessList::decode_from(iter.next().unwrap())?)
                    .take_and_build_payload_eip_2930()
                    .map_err(|_| RlpDataDecodingError::InvalidFormat)?;

                let y_parity_u64 = u64::decode_from(iter.next().unwrap())?;
                let y_parity_u8 = u8::try_from(y_parity_u64)
                    .map_err(|_| RlpDataDecodingError::InvalidFormat)?;
                let y_parity = match YParity::from_u8(y_parity_u8) {
                    None => {
                        return Err(RlpDataDecodingError::InvalidFormat);
                    }
                    Some(y_parity) => y_parity,
                };
                let r = BigUint::decode_from(iter.next().unwrap())?;
                let s = BigUint::decode_from(iter.next().unwrap())?;
                Ok(TransactionEip2930 {
                    payload,
                    y_parity,
                    r,
                    s,
                })
            }
        };
    }
}
