// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigUint;
use crate::blockchain::ethereum::transaction::builder::TransactionBuildingError;
use crate::blockchain::ethereum::transaction::payload::legacy::PayloadLegacy;
use crate::crypto::ecdsa::{ecdsa_signing, PrivateKey, SigningOptions};
use crate::crypto::hash::{Keccak256, UnkeyedHash};
use crate::tools::codable::encode;
use std::fmt;
use std::fmt::Display;

pub struct TransactionLegacy {
    pub(crate) payload: PayloadLegacy,
    pub(crate) v: u8,
    pub(crate) r: BigUint,
    pub(crate) s: BigUint,
}

impl TransactionLegacy {
    pub fn encode(&self) -> Vec<u8> {
        encode(self)
    }
}

impl PayloadLegacy {
    pub fn take_and_sign_with_options(
        self,
        private_key: &PrivateKey,
        options: &SigningOptions,
    ) -> Result<TransactionLegacy, TransactionBuildingError> {
        let rlp_data = encode(&self);
        let hash = Keccak256::new().digest(rlp_data);

        let (signature, recovery_id) =
            ecdsa_signing::sign_with_options(&hash, private_key, options)
                .map_err(TransactionBuildingError::SigningError)?;
        let r = BigUint::from_bigint(signature.r).unwrap();
        let s = BigUint::from_bigint(signature.s).unwrap();

        // "...Tw = 27 + Ty..."
        // See Ethereum Yellow Paper, 4.2. The Transaction.
        let v = 27 + recovery_id.y_parity() as u8;

        Ok(TransactionLegacy {
            payload: self,
            v,
            r,
            s,
        })
    }
}

impl Display for TransactionLegacy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "==================")?;
        writeln!(f, "Transaction Legacy")?;
        writeln!(f, "==================")?;
        writeln!(f)?;
        writeln!(f, "-------")?;
        writeln!(f, "Payload")?;
        writeln!(f, "-------")?;
        writeln!(f, "{}", self.payload)?;

        writeln!(f, "---------")?;
        writeln!(f, "Signature")?;
        writeln!(f, "---------")?;
        writeln!(f, "v: 0x{:x} ({})", self.v, self.v)?;
        writeln!(f, "r: {}", self.r)?;
        writeln!(f, "s: {}", self.s)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::bigint::{BigInt, BigUint};
    use crate::blockchain::ethereum::transaction::builder::TransactionBuilder;
    use crate::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
    use crate::crypto::ecdsa::{PrivateKey, SigningOptions};
    use crate::crypto::secp256k1;

    #[test]
    fn test_common() {
        let curve = secp256k1();
        let d = BigInt::from_hex(
            "164122e5d39e9814ca723a749253663bafb07f6af91704d9754c361eb315f0c1",
        )
        .unwrap();
        let private_key = PrivateKey::new(d, curve).unwrap();

        let transaction = TransactionBuilder::new()
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
                "f889808609184e72a0008227109400000000",
                "0000000000000000000000000000000080a4",
                "7f7465737432000000000000000000000000",
                "000000000000000000000000000000600057",
                "1ba070bad1a10475d4b24e8227978077233c",
                "3367a7642701db223465793e68d368b3a07e",
                "3d131ef92c04eca4e48f1f5c0d2ea971f280",
                "2d0e61ec21c8354b605ad286c0"
            )
        );
    }
}
