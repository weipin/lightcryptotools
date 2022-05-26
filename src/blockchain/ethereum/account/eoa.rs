// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements EOA (externally-owned account) related functions.

use crate::bigint;
use crate::bigint::BigInt;
use crate::crypto::codecs::bytes_to_lower_hex;
use crate::crypto::ecdsa::{PrivateKey, PublicKey};
use crate::crypto::hash::{Keccak256, UnkeyedHash};
use crate::crypto::secp256k1;
use std::fmt;
use std::fmt::Display;
use std::iter::zip;

pub type EoaPrivateKeyData = [u8; 32]; // 32: length of Secp256k1 base point order in bytes

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
    pub fn address(&self) -> EoaPublicAddress {
        // Takes the last 20 bytes of the Keccak-256 hash of the public key
        let bytes = self.0.curve_params.point_to_bytes(&self.0.data);
        let address_data: [u8; 20] = Keccak256::new().digest(bytes)[12..].try_into().unwrap();
        EoaPublicAddress(address_data)
    }
}

// Public address of an externally-owned account.
pub struct EoaPublicAddress(pub [u8; 20]);

impl EoaPublicAddress {
    fn to_hex(&self) -> String {
        bytes_to_lower_hex(&self.0)
    }

    fn to_checksummed_hex(&self) -> String {
        let hex = self.to_hex();
        String::from_utf8(eip_55_checksum_encode(hex.as_bytes())).unwrap()
    }
}

impl Display for EoaPublicAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let checksummed_hex = self.to_checksummed_hex();
        write!(f, "0x{checksummed_hex}")
    }
}

// Returns checksummed `address_lower_hex`.
//
// `address_lower_hex` is the hexadecimal of an EOA address and it
// 1. must be lower-case
// 2. must not be prefixed with "0x"
//
// See EIP-55 for details:
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
// https://github.com/ethereum/EIPs/commit/54f9d55ee71b7099164c77422f30430a5ad4afa2
fn eip_55_checksum_encode(address_lower_hex: &[u8]) -> Vec<u8> {
    let hashed_address_lower_hex =
        bytes_to_lower_hex(&Keccak256::new().digest(address_lower_hex));
    let mut checksummed_address_hex = Vec::with_capacity(address_lower_hex.len());
    for (&c1, &c2) in zip(address_lower_hex, hashed_address_lower_hex.as_bytes()) {
        match c1 {
            b'0'..=b'9' => checksummed_address_hex.push(c1),
            b'a'..=b'f' => {
                if c2 > b'7' {
                    checksummed_address_hex.push(c1 - 32); // to uppercase
                } else {
                    checksummed_address_hex.push(c1);
                }
            }
            _ => {
                panic!("found invalid char")
            }
        }
    }

    assert_eq!(checksummed_address_hex.len(), 40); // Respects the EIP
    checksummed_address_hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing_tools::ethereum::private_key_hex_to_address;

    #[test]
    fn test_eip_55_checksum_encoding() {
        let data = [
            // All caps
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
            // All Lower
            "0xde709f2102306220921060314715629080e2fb77",
            "0x27b1fdb04752bbc536007a920d24acb045561c26",
            // Normal
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ];

        for address in data {
            let lower_address = address.to_lowercase();
            let input = &lower_address.as_bytes()[2..];
            let result = eip_55_checksum_encode(input);
            assert_eq!(result, address.as_bytes()[2..]);
        }
    }

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
