// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::path::integration_testing_data_path;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::codecs::hex_to_bytes;
use lightcryptotools::crypto::ecdsa::{sign, sign_with_options, PrivateKey, SigningOptions};
use lightcryptotools::crypto::secp256k1;
use serde_json::Value;
use std::fs::File;

#[test]
fn test_ecdsa_secp256k1_signing_cases() {
    let secp256k1 = secp256k1();

    // (hash, d, signature)
    let data = [(
        "06ef2b193b83b3d701f765f1db34672ab84897e1252343cc2197829af3a30456",
        "1",
        concat!(
            "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c9",
            "907f867d799087a2c09be72dbe9c2250a9335f31d94ab034a1f1f4927c021edf"
        ),
    )];

    for (hash_hex, d_hex, signature_hex) in data {
        let private_key = PrivateKey {
            data: BigInt::from_hex(d_hex).unwrap(),
            curve_domain: secp256k1,
        };
        let signature = sign_with_options(
            &hex_to_bytes(hash_hex).unwrap(),
            &private_key,
            &SigningOptions {
                enforce_low_s: false,
                ..Default::default()
            },
        );

        let hex = signature.to_hex();
        assert_eq!(hex, signature_hex);
    }
}

#[test]
#[ignore]
fn test_signing() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/ecdsa.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["valid"].as_array().unwrap();
    for value in value_vec {
        let d_hex = value["d"].as_str().unwrap();
        let m_hex = value["m"].as_str().unwrap();
        let signature_hex = value["signature"].as_str().unwrap();

        let private_key = PrivateKey {
            data: BigInt::from_hex(d_hex).unwrap(),
            curve_domain: secp256k1,
        };
        let signature = sign(&hex_to_bytes(m_hex).unwrap(), &private_key);
        assert_eq!(signature.to_hex(), signature_hex);
    }
}
