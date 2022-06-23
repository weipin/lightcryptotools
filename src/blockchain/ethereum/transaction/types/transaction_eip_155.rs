// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigUint;
use crate::blockchain::ethereum::transaction::builder::TransactionBuildingError;
use crate::blockchain::ethereum::transaction::payload::eip_155::PayloadEip155;
use crate::crypto::ecdsa::{ecdsa_signing, PrivateKey, SigningOptions};
use crate::crypto::hash::{Keccak256, UnkeyedHash};
use crate::tools::codable::encode;
use std::fmt;
use std::fmt::Display;

pub struct TransactionEip155 {
    pub(crate) payload: PayloadEip155,
    pub(crate) v: BigUint,
    pub(crate) r: BigUint,
    pub(crate) s: BigUint,
}

impl TransactionEip155 {
    pub fn encode(&self) -> Vec<u8> {
        encode(self)
    }
}

impl PayloadEip155 {
    pub fn take_and_sign_with_options(
        self,
        private_key: &PrivateKey,
        options: &SigningOptions,
    ) -> Result<TransactionEip155, TransactionBuildingError> {
        let rlp_data = encode(&self);
        let hash = Keccak256::new().digest(rlp_data);

        let (signature, recovery_id) =
            ecdsa_signing::sign_with_options(&hash, private_key, options)
                .map_err(TransactionBuildingError::SigningError)?;
        let r = BigUint::from_bigint(signature.r).unwrap();
        let s = BigUint::from_bigint(signature.s).unwrap();

        // "...v of the signature MUST be set to {0,1} + CHAIN_ID * 2 + 35..."
        // See EIP 155.
        let v = BigUint::from(recovery_id.y_parity() as u8)
            + &self.chain_id.0 * BigUint::from(2_u8)
            + BigUint::from(35_u8);

        Ok(TransactionEip155 {
            payload: self,
            v,
            r,
            s,
        })
    }
}

impl Display for TransactionEip155 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "===================")?;
        writeln!(f, "Transaction EIP 155")?;
        writeln!(f, "===================")?;
        writeln!(f)?;
        writeln!(f, "-------")?;
        writeln!(f, "Payload")?;
        writeln!(f, "-------")?;
        writeln!(f, "{}", self.payload)?;

        writeln!(f, "---------")?;
        writeln!(f, "Signature")?;
        writeln!(f, "---------")?;
        writeln!(f, "v: {}", self.v)?;
        writeln!(f, "r: {}", self.r)?;
        writeln!(f, "s: {}", self.s)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::bigint::{BigInt, BigUint};
    use crate::blockchain::ethereum::transaction::builder::TransactionBuilder;
    use crate::blockchain::ethereum::types::Chain;
    use crate::crypto::codecs::bytes_to_lower_hex;
    use crate::crypto::ecdsa::{PrivateKey, SigningOptions};
    use crate::crypto::secp256k1;

    // The test data is from EIP-155
    #[test]
    fn test_common() {
        let curve = secp256k1();
        let d = BigInt::from_hex(
            "4646464646464646464646464646464646464646464646464646464646464646",
        )
        .unwrap();
        let private_key = PrivateKey::new(d, curve).unwrap();

        let transaction = TransactionBuilder::new()
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
            .unwrap()
            .take_and_sign_with_options(
                &private_key,
                &SigningOptions {
                    employ_extra_random_data: false,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(transaction.v, BigUint::from(37_u8));
        assert_eq!(
            transaction.r,
            BigUint::from_str_radix(
                "18515461264373351373200002665853028612451056578545711640558177340181847433846",
                10
            )
            .unwrap()
        );
        assert_eq!(
            transaction.s,
            BigUint::from_str_radix(
                "46948507304638947509940763649030358759909902576025900602547168820602576006531",
                10
            )
            .unwrap()
        );

        assert_eq!(
            bytes_to_lower_hex(&transaction.encode()),
            concat!(
                "f86c098504a817c800825208943535353535",
                "353535353535353535353535353535880de0",
                "b6b3a76400008025a028ef61340bd939bc21",
                "95fe537567866003e1a15d3c71ff63e15906",
                "20aa636276a067cbe9d8997f761aecb70330",
                "4b3800ccf555c9f3dc64214b297fb1966a3b6d83",
            )
        );
    }
}
