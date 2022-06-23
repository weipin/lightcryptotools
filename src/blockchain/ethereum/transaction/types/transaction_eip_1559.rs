// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigUint;
use crate::blockchain::ethereum::transaction::payload::eip_1559::PayloadEip1559;
use crate::blockchain::ethereum::transaction::TransactionBuildingError;
use crate::blockchain::ethereum::types::TransactionType;
use crate::crypto::ecdsa::ecdsa_core::YParity;
use crate::crypto::ecdsa::{ecdsa_signing, PrivateKey, SigningOptions};
use crate::crypto::hash::{Keccak256, UnkeyedHash};
use crate::tools::codable::encode;
use std::fmt;
use std::fmt::Display;

pub struct TransactionEip1559 {
    pub(crate) payload: PayloadEip1559,
    pub(crate) y_parity: YParity,
    pub(crate) r: BigUint,
    pub(crate) s: BigUint,
}

impl TransactionEip1559 {
    pub fn transaction_type() -> TransactionType {
        0x2
    }
}

impl PayloadEip1559 {
    pub fn take_and_sign_with_options(
        self,
        private_key: &PrivateKey,
        options: &SigningOptions,
    ) -> Result<TransactionEip1559, TransactionBuildingError> {
        let mut payload_rlp_data = encode(&self);
        let mut message = Vec::with_capacity(payload_rlp_data.len() + 1);
        message.push(TransactionEip1559::transaction_type());
        message.append(&mut payload_rlp_data);
        let hash = Keccak256::new().digest(message);

        let (signature, recovery_id) =
            ecdsa_signing::sign_with_options(&hash, private_key, options)
                .map_err(TransactionBuildingError::SigningError)?;
        let y_parity = recovery_id.y_parity();
        let r = BigUint::from_bigint(signature.r).unwrap();
        let s = BigUint::from_bigint(signature.s).unwrap();

        Ok(TransactionEip1559 {
            payload: self,
            y_parity,
            r,
            s,
        })
    }
}

impl TransactionEip1559 {
    pub fn encode(&self) -> Vec<u8> {
        let mut rlp_data = encode(self);
        let mut data = Vec::with_capacity(rlp_data.len() + 1);

        data.push(TransactionEip1559::transaction_type());
        data.append(&mut rlp_data);

        data
    }
}

impl Display for TransactionEip1559 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "====================")?;
        writeln!(f, "Transaction EIP 1559")?;
        writeln!(f, "====================")?;
        writeln!(f)?;
        writeln!(f, "-------")?;
        writeln!(f, "Payload")?;
        writeln!(f, "-------")?;
        writeln!(f, "{}", self.payload)?;

        writeln!(f, "---------")?;
        writeln!(f, "Signature")?;
        writeln!(f, "---------")?;
        writeln!(f, "y_parity: {}", self.y_parity)?;
        writeln!(f, "r: {}", self.r)?;
        writeln!(f, "s: {}", self.s)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::bigint::BigInt;
    use crate::blockchain::ethereum::transaction::TransactionBuilder;
    use crate::blockchain::ethereum::types::{AccessList, AccessListItem};
    use crate::crypto::codecs::bytes_to_lower_hex;
    use crate::crypto::ecdsa::{PrivateKey, SigningOptions};
    use crate::crypto::secp256k1;

    #[test]
    fn test_common() {
        let curve = secp256k1();
        let d = BigInt::from_hex(
            "89f8496f444e0bbb708eaad5e7ed1d71fd9c4d7977a39f7c6a6f1cf0aefd0a6d",
        )
        .unwrap();
        let private_key = PrivateKey::new(d, curve).unwrap();

        let transaction = TransactionBuilder::new()
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
            .unwrap()
            .take_and_sign_with_options(
                &private_key,
                &SigningOptions {
                    employ_extra_random_data: false,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(
            bytes_to_lower_hex(&transaction.encode()),
            concat!(
                "02f89f7b2a4282014382520894123456789a",
                "123456789a123456789a123456789a820123",
                "80f838f794123456789a123456789a123456",
                "789a123456789ae1a00123456789abcdef01",
                "23456789abcdef0123456789abcdef012345",
                "6789abcdef80a02cd518c375dfd2231b9352",
                "e600a559cd1c7dd38ed46f4e470bde6723aa",
                "85ab90a0432f760d25c8aa48ee9933b81821",
                "b37a7408b45a253f0639a7875fe64f49f0b6"
            )
        );
    }
}
