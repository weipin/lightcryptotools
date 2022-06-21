// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements EOA (externally-owned account) related functions.

use crate::bigint;
use crate::bigint::BigInt;
use crate::blockchain::ethereum::types::Address;
use crate::crypto::ecdsa::{PrivateKey, PublicKey};
use crate::crypto::hash::{Keccak256, UnkeyedHash};
use crate::crypto::secp256k1;

pub const EOA_PRIVATE_KEY_DATA_BYTE_LENGTH: usize = 32;
pub type EoaPrivateKeyData = [u8; EOA_PRIVATE_KEY_DATA_BYTE_LENGTH];

// Private key of an externally-owned account.
pub struct EoaPrivateKey<'a>(pub PrivateKey<'a>);

impl EoaPrivateKey<'_> {
    pub fn new(data: EoaPrivateKeyData) -> Option<EoaPrivateKey<'static>> {
        let d = BigInt::from_be_bytes(&data, bigint::Sign::Positive);
        PrivateKey::new(d, secp256k1()).map(EoaPrivateKey)
    }

    pub fn public_key(&self) -> EoaPublicKey {
        EoaPublicKey(self.0.public_key())
    }
}

// Public key of an externally-owned account.
pub struct EoaPublicKey<'a>(pub PublicKey<'a>);

impl EoaPublicKey<'_> {
    pub fn address(&self) -> Address {
        // Takes the last 20 bytes of the Keccak-256 hash of the public key
        let bytes = self.0.curve_params.point_to_bytes(&self.0.data);
        Address::from_bytes(&Keccak256::new().digest(bytes)[12..]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::testing_tools::ethereum::private_key_hex_to_address;

    #[test]
    fn test_private_key_to_address() {
        // Test vector from "ethereum/tests":
        //
        // https://github.com/ethereum/tests/blob/develop/BasicTests/keyaddrtest.json
        // https://etherscan.io/address/0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826
        let data = [
            (
                "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
                "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
            ),
            (
                "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0",
                "0x13978aee95f38490e9769C39B2773Ed763d9cd5F",
            ),
        ];
        for (key_hex, address_display) in data {
            assert_eq!(private_key_hex_to_address(key_hex), address_display);
        }
    }

    #[test]
    fn test_private_key_to_address_with_padded_public_key() {
        // https://github.com/ethereumjs/ethereumjs-util/commit/8aafe005ea86c2e5bcba94813ea98d8e3ec0522f
        // https://www.reddit.com/r/ethereum/comments/47nkoi/psa_check_your_ethaddressorg_wallets_and_any/
        // https://www.reddit.com/r/ethereum/comments/48rt6n/using_myetherwalletcom_just_burned_me_for/
        // https://etherscan.io/address/0x2F015C60E0be116B1f0CD534704Db9c92118FB6A

        let key_hex = "ea54bdc52d163f88c93ab0615782cf718a2efb9e51a7989aab1b08067e9c1c5f";
        let address = "0x2F015C60E0be116B1f0CD534704Db9c92118FB6A";
        assert_eq!(private_key_hex_to_address(key_hex), address);
    }
}
