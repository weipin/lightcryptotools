// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::curves::*;
use devtools::path::integration_testing_data_path;
use lightcryptotools::crypto::codecs::hex_to_bytes;
use lightcryptotools::crypto::ecdsa::{
    verify_with_options, PublicKey, Signature, VerifyingOptions,
};
use lightcryptotools::crypto::{secp256k1, EllipticCurveParams};
use ring::digest;
use serde_json::Value;
use std::fs::File;

#[test]
#[ignore]
fn test_ecdsa_wycheproof() {
    let data = [
        (
            &brainpool_p256r1(),
            "ecdsa_brainpoolP256r1_sha256_p1363_test.json",
            &digest::SHA256,
        ),
        (
            &brainpool_p320r1(),
            "ecdsa_brainpoolP320r1_sha384_p1363_test.json",
            &digest::SHA384,
        ),
        (
            &brainpool_p384r1(),
            "ecdsa_brainpoolP384r1_sha384_p1363_test.json",
            &digest::SHA384,
        ),
        (
            &brainpool_p512r1(),
            "ecdsa_brainpoolP512r1_sha512_p1363_test.json",
            &digest::SHA512,
        ),
        (
            &secp224r1(),
            "ecdsa_secp224r1_sha256_p1363_test.json",
            &digest::SHA256,
        ),
        (
            &secp224r1(),
            "ecdsa_secp224r1_sha512_p1363_test.json",
            &digest::SHA512,
        ),
        (
            secp256k1(),
            "ecdsa_secp256k1_sha256_p1363_test.json",
            &digest::SHA256,
        ),
        (
            secp256k1(),
            "ecdsa_secp256k1_sha512_p1363_test.json",
            &digest::SHA512,
        ),
        (
            &secp256r1(),
            "ecdsa_secp256r1_sha256_p1363_test.json",
            &digest::SHA256,
        ),
        (
            &secp256r1(),
            "ecdsa_secp256r1_sha512_p1363_test.json",
            &digest::SHA512,
        ),
        (
            &secp384r1(),
            "ecdsa_secp384r1_sha384_p1363_test.json",
            &digest::SHA384,
        ),
        (
            &secp384r1(),
            "ecdsa_secp384r1_sha512_p1363_test.json",
            &digest::SHA512,
        ),
        (
            &secp521r1(),
            "ecdsa_secp521r1_sha512_p1363_test.json",
            &digest::SHA512,
        ),
    ];

    for (curve, data_filename, algorithm) in data {
        test_ecdsa_wycheproof_p1363(curve, data_filename, algorithm);
    }
}

fn test_ecdsa_wycheproof_p1363(
    curve: &EllipticCurveParams,
    data_filename: &str,
    algorithm: &'static digest::Algorithm,
) {
    let path = integration_testing_data_path(&format!("crypto/wycheproof/{data_filename}"));
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();

    let group_vec = root["testGroups"].as_array().unwrap();
    for group in group_vec {
        let public_key_hex = group["key"]["uncompressed"].as_str().unwrap();
        let public_key = PublicKey::from_sec1_hex(public_key_hex, &curve).unwrap();

        let value_vec = group["tests"].as_array().unwrap();
        for value in value_vec {
            let m_hex = value["msg"].as_str().unwrap();
            let signature_hex = value["sig"].as_str().unwrap();
            let result_str = value["result"].as_str().unwrap();

            let signature = match Signature::from_p1363_hex(signature_hex, &curve) {
                Ok(x) => x,
                Err(_) => {
                    assert!(result_str == "invalid" || result_str == "acceptable");
                    continue;
                }
            };

            let mut context = digest::Context::new(algorithm);
            context.update(&hex_to_bytes(m_hex).unwrap());
            let digest = context.finish();
            let hash = digest.as_ref();

            let enforce_low_s = false;
            let strict_hash_byte_length = false;
            let result = verify_with_options(
                hash,
                &signature,
                &public_key,
                &VerifyingOptions {
                    enforce_low_s,
                    strict_hash_byte_length,
                },
            );
            if result.is_err() {
                assert_eq!(result_str, "invalid");
            } else {
                if result.unwrap() {
                    assert_eq!(result_str, "valid");
                } else {
                    assert_eq!(result_str, "invalid");
                }
            }
        } // tests
    } // group_vec
}
