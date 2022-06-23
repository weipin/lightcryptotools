// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::blockchain::ethereum::transaction::builder::{
    TransactionBuilder, TransactionBuildingError,
};
use crate::blockchain::ethereum::types::address::Address;
use crate::blockchain::ethereum::types::currency_unit::Wei;
use crate::blockchain::ethereum::types::eoa_nonce::EoaNonce;
use crate::crypto::codecs::bytes_to_lower_hex;
use std::fmt;
use std::fmt::Display;

pub struct PayloadLegacy {
    pub(crate) nonce: EoaNonce,
    pub(crate) gas_price: Wei,
    pub(crate) gas_limit: u64,
    pub(crate) destination: Address,
    pub(crate) amount: Wei,
    pub(crate) data: Vec<u8>,
}

impl TransactionBuilder {
    pub fn take_and_build_payload_legacy(
        &mut self,
    ) -> Result<PayloadLegacy, TransactionBuildingError> {
        if self.nonce.is_none()
            || self.gas_price.is_none()
            || self.gas_limit.is_none()
            || self.destination.is_none()
            || self.amount.is_none()
        {
            Err(TransactionBuildingError::MissingFields)
        } else {
            let nonce = self.nonce.take().unwrap();
            let gas_price = self.gas_price.take().unwrap();
            let gas_limit = self.gas_limit.take().unwrap();
            let destination = self.destination.take().unwrap();
            let amount = self.amount.take().unwrap();
            let data = self.data.take().unwrap_or_default();

            Ok(PayloadLegacy {
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

impl Display for PayloadLegacy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "nonce: {}", self.nonce)?;
        writeln!(f, "gas_price: {}", self.gas_price)?;
        writeln!(f, "gas_limit: 0x{:x}", self.gas_limit)?;
        writeln!(f, "destination: {}", self.destination)?;
        writeln!(f, "amount: {}", self.amount)?;
        writeln!(f, "data: 0x{}", bytes_to_lower_hex(&self.data))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::BigUint;
    use crate::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
    use crate::tools::codable::encode;

    #[test]
    fn test_common() {
        let payload = TransactionBuilder::new()
            .with_nonce(0.try_into().unwrap())
            .with_gas_price("0x09184e72a000".try_into().unwrap())
            .with_gas_limit(0x2710)
            .with_destination(
                "0x0000000000000000000000000000000000000000"
                    .try_into()
                    .unwrap(),
            )
            .with_amount(BigUint::from(0_u8).into())
            .with_data(
                hex_to_bytes(
                    "7f7465737432000000000000000000000000000000000000000000000000000000600057",
                )
                .unwrap(),
            )
            .take_and_build_payload_legacy()
            .unwrap();

        let rlp_data = encode(&payload);
        assert_eq!(
            bytes_to_lower_hex(&rlp_data),
            concat!(
                "f846808609184e72a0008227109400000000",
                "0000000000000000000000000000000080a4",
                "7f7465737432000000000000000000000000",
                "000000000000000000000000000000600057"
            )
        );
    }
}
