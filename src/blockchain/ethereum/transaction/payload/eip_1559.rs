// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::blockchain::ethereum::transaction::{TransactionBuilder, TransactionBuildingError};
use crate::blockchain::ethereum::types::{AccessList, Address, ChainId, EoaNonce, Wei};

pub struct PayloadEip1559 {
    pub(crate) chain_id: ChainId,
    pub(crate) nonce: EoaNonce,
    pub(crate) max_priority_fee_per_gas: Wei,
    pub(crate) max_fee_per_gas: Wei,
    pub(crate) gas_limit: u64,
    pub(crate) destination: Address,
    pub(crate) amount: Wei,
    pub(crate) data: Vec<u8>,
    pub(crate) access_list: AccessList,
}

impl TransactionBuilder {
    pub fn take_and_build_payload_eip_1559(
        &mut self,
    ) -> Result<PayloadEip1559, TransactionBuildingError> {
        if self.chain_id.is_none()
            || self.nonce.is_none()
            || self.max_priority_fee_per_gas.is_none()
            || self.max_fee_per_gas.is_none()
            || self.gas_limit.is_none()
            || self.destination.is_none()
            || self.amount.is_none()
        {
            Err(TransactionBuildingError::MissingFields)
        } else {
            let chain_id = self.chain_id.take().unwrap();
            let nonce = self.nonce.take().unwrap();
            let max_priority_fee_per_gas = self.max_priority_fee_per_gas.take().unwrap();
            let max_fee_per_gas = self.max_fee_per_gas.take().unwrap();
            let gas_limit = self.gas_limit.take().unwrap();
            let destination = self.destination.take().unwrap();
            let amount = self.amount.take().unwrap();
            let data = self.data.take().unwrap_or_default();
            let access_list = self.access_list.take().unwrap_or_default();

            Ok(PayloadEip1559 {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
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
    use crate::blockchain::ethereum::types::AccessListItem;
    use crate::crypto::codecs::bytes_to_lower_hex;
    use crate::tools::codable::encode;

    #[test]
    fn test_common() {
        let payload = TransactionBuilder::new()
            .with_chain_id(123.into())
            .with_nonce(42.try_into().unwrap())
            .with_max_priority_fee_per_gas("0x42".try_into().unwrap())
            .with_max_fee_per_gas("0x0143".try_into().unwrap())
            .with_gas_limit(0x5208)
            .with_destination(
                "0x123456789a123456789a123456789a123456789a"
                    .try_into()
                    .unwrap(),
            )
            .with_amount("0x0123".try_into().unwrap())
            .with_access_list(AccessList(vec![AccessListItem {
                address: "0x123456789a123456789a123456789a123456789a"
                    .try_into()
                    .unwrap(),
                storage_keys: vec![
                    "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .try_into()
                        .unwrap(),
                ],
            }]))
            .take_and_build_payload_eip_1559()
            .unwrap();

        let rlp_data = encode(&payload);
        assert_eq!(
            bytes_to_lower_hex(&rlp_data),
            concat!(
                "f85c7b2a4282014382520894123456789a12",
                "3456789a123456789a123456789a82012380",
                "f838f794123456789a123456789a12345678",
                "9a123456789ae1a00123456789abcdef0123",
                "456789abcdef0123456789abcdef0123456789abcdef"
            )
        );
    }
}
