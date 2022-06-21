// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::blockchain::ethereum::transaction::{TransactionBuilder, TransactionBuildingError};
use crate::blockchain::ethereum::types::{AccessList, Address, ChainId, EoaNonce, Wei};

pub struct PayloadEip2930 {
    pub(crate) chain_id: ChainId,
    pub(crate) nonce: EoaNonce,
    pub(crate) gas_price: Wei,
    pub(crate) gas_limit: u64,
    pub(crate) destination: Address,
    pub(crate) amount: Wei,
    pub(crate) data: Vec<u8>,
    pub(crate) access_list: AccessList,
}

impl TransactionBuilder {
    pub fn take_and_build_payload_eip_2930(
        &mut self,
    ) -> Result<PayloadEip2930, TransactionBuildingError> {
        if self.chain_id.is_none()
            || self.nonce.is_none()
            || self.gas_price.is_none()
            || self.gas_limit.is_none()
            || self.destination.is_none()
            || self.amount.is_none()
        {
            Err(TransactionBuildingError::MissingFields)
        } else {
            let chain_id = self.chain_id.take().unwrap();
            let nonce = self.nonce.take().unwrap();
            let gas_price = self.gas_price.take().unwrap();
            let gas_limit = self.gas_limit.take().unwrap();
            let destination = self.destination.take().unwrap();
            let amount = self.amount.take().unwrap();
            let data = self.data.take().unwrap_or_default();
            let access_list = self.access_list.take().unwrap_or_default();

            Ok(PayloadEip2930 {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                destination,
                amount,
                data,
                access_list,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
    use crate::tools::codable::encode;

    #[test]
    fn test_common() {
        let payload = TransactionBuilder::new()
            .with_chain_id(144.into())
            .with_nonce(9.try_into().unwrap())
            .with_gas_price("0x765898be".try_into().unwrap())
            .with_gas_limit(0xbb)
            .with_destination(
                "0xf933abf2475062e0f3e7bde89da3f6c9e6963b67"
                    .try_into()
                    .unwrap(),
            )
            .with_amount("0xd7".try_into().unwrap())
            .with_data(hex_to_bytes("74a53d7a649760e78359").unwrap())
            .take_and_build_payload_eip_2930()
            .unwrap();

        let rlp_data = encode(&payload);
        assert_eq!(
            bytes_to_lower_hex(&rlp_data),
            concat!(
                "ed81900984765898be81bb94f933abf24750",
                "62e0f3e7bde89da3f6c9e6963b6781d78a74",
                "a53d7a649760e78359c0",
            )
        );
    }
}
