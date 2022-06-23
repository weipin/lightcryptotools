// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigUint;
use crate::blockchain::ethereum::transaction::payload::eip_2930::PayloadEip2930;
use crate::blockchain::ethereum::transaction::TransactionBuildingError;
use crate::blockchain::ethereum::types::TransactionType;
use crate::crypto::ecdsa::ecdsa_core::YParity;
use crate::crypto::ecdsa::{ecdsa_signing, PrivateKey, SigningOptions};
use crate::crypto::hash::{Keccak256, UnkeyedHash};
use crate::tools::codable::encode;
use std::fmt;
use std::fmt::Display;

pub struct TransactionEip2930 {
    pub(crate) payload: PayloadEip2930,
    pub(crate) y_parity: YParity,
    pub(crate) r: BigUint,
    pub(crate) s: BigUint,
}

impl TransactionEip2930 {
    pub fn transaction_type() -> TransactionType {
        0x1
    }
}

impl PayloadEip2930 {
    pub fn take_and_sign_with_options(
        self,
        private_key: &PrivateKey,
        options: &SigningOptions,
    ) -> Result<TransactionEip2930, TransactionBuildingError> {
        // ...The signatureYParity, signatureR, signatureS elements of this transaction
        // represent a secp256k1 signature over
        // keccak256(0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList]))...
        //
        // -- from EIP-2930
        let mut payload_rlp_data = encode(&self);
        let mut message = Vec::with_capacity(payload_rlp_data.len() + 1);
        message.push(TransactionEip2930::transaction_type());
        message.append(&mut payload_rlp_data);
        let hash = Keccak256::new().digest(message);

        let (signature, recovery_id) =
            ecdsa_signing::sign_with_options(&hash, private_key, options)
                .map_err(TransactionBuildingError::SigningError)?;
        let y_parity = recovery_id.y_parity();
        let r = BigUint::from_bigint(signature.r).unwrap();
        let s = BigUint::from_bigint(signature.s).unwrap();

        Ok(TransactionEip2930 {
            payload: self,
            y_parity,
            r,
            s,
        })
    }
}

impl TransactionEip2930 {
    pub fn encode(&self) -> Vec<u8> {
        let mut rlp_data = encode(self);
        let mut data = Vec::with_capacity(rlp_data.len() + 1);

        data.push(TransactionEip2930::transaction_type());
        data.append(&mut rlp_data);

        data
    }
}

impl Display for TransactionEip2930 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "====================")?;
        writeln!(f, "Transaction EIP 2930")?;
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
    use crate::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
    use crate::crypto::ecdsa::{PrivateKey, SigningOptions};
    use crate::crypto::secp256k1;

    #[test]
    fn test_common() {
        let curve = secp256k1();
        let d = BigInt::from_hex(
            "7281c3c5250fb36465366adb782e4e997f44271e6ae16847f45f3f7d5054217e",
        )
        .unwrap();
        let private_key = PrivateKey::new(d, curve).unwrap();

        let transaction = TransactionBuilder::new()
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
                "01f87081900984765898be81bb94f933abf2",
                "475062e0f3e7bde89da3f6c9e6963b6781d7",
                "8a74a53d7a649760e78359c001a07796c9c6",
                "e8e07fd5b084b720679f0a77995ef6d3c61c",
                "d669f2a4f756e29838c1a00511904f04111b",
                "7d90322aa9a74159d8ca44b8b852aa37fa6f",
                "a3996b851956bd"
            )
        );
    }
}
