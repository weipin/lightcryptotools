// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::blockchain::ethereum::transaction::{TransactionBuilder, TransactionBuildingError};
use crate::blockchain::ethereum::types::address::Address;
use crate::blockchain::ethereum::types::eoa_nonce::EoaNonce;
use crate::blockchain::ethereum::types::{ChainId, Wei};

pub struct PayloadEip155 {
    pub(crate) chain_id: ChainId,
    pub(crate) nonce: EoaNonce,
    pub(crate) gas_price: Wei,
    pub(crate) gas_limit: u64,
    pub(crate) destination: Address,
    pub(crate) amount: Wei,
    pub(crate) data: Vec<u8>,
}

impl TransactionBuilder {
    pub fn take_and_build_payload_eip_155(
        &mut self,
    ) -> Result<PayloadEip155, TransactionBuildingError> {
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

            Ok(PayloadEip155 {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                destination,
                amount,
                data,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::ethereum::types::Chain;
    use crate::crypto::codecs::bytes_to_lower_hex;
    use crate::tools::codable::encode;

    // The test data is from EIP-155
    #[test]
    fn test_common() {
        let payload = TransactionBuilder::new()
            .with_chain_id(Chain::EthereumMainnet.id())
            .with_nonce(9.try_into().unwrap())
            .with_gas_price("20000000000".try_into().unwrap())
            .with_gas_limit(21000)
            .with_destination(
                "0x3535353535353535353535353535353535353535"
                    .try_into()
                    .unwrap(),
            )
            .with_amount("1000000000000000000".try_into().unwrap())
            .take_and_build_payload_eip_155()
            .unwrap();

        let rlp_data = encode(&payload);
        assert_eq!(
            bytes_to_lower_hex(&rlp_data),
            concat!(
                "ec098504a817c80082520894353535353535",
                "3535353535353535353535353535880de0b6",
                "b3a764000080018080",
            )
        );
    }
}
