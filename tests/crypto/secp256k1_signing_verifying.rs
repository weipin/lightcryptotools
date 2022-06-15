// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::path::integration_testing_data_path;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::codecs::hex_to_bytes;
use lightcryptotools::crypto::ecdsa::{
    sign_with_options, verify, verify_with_options, PrivateKey, PublicKey, Signature,
    SigningOptions, VerifyingOptions,
};
use lightcryptotools::crypto::secp256k1;
use serde_json::Value;
use std::fs::File;

#[test]
fn test_ecdsa_secp256k1_signing_cases() {
    let secp256k1 = secp256k1();

    // (hash, d, signature)
    let data = [(
        "06ef2b193b83b3d701f765f1db34672ab84897e1252343cc2197829af3a30456",
        "01",
        concat!(
            "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c9",
            "907f867d799087a2c09be72dbe9c2250a9335f31d94ab034a1f1f4927c021edf"
        ),
    )];

    for (hash_hex, d_hex, signature_hex) in data {
        let private_key = PrivateKey::new(BigInt::from_hex(d_hex).unwrap(), secp256k1).unwrap();
        let (signature, _) = sign_with_options(
            &hex_to_bytes(hash_hex).unwrap(),
            &private_key,
            &SigningOptions {
                enforce_low_s: false,
                employ_extra_random_data: false,
                ..Default::default()
            },
        )
        .unwrap();

        let hex = signature.to_p1363_hex();
        assert_eq!(hex, signature_hex);
    }
}

#[test]
fn test_verify_non_strict_msg_bb5a() {
    // should verify non-strict msg bb5a...(adapted from noble-secp256k1)
    let secp256k1 = secp256k1();

    let hash_hex = "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023";
    let x_decimal =
        "3252872872578928810725465493269682203671229454553002637820453004368632726370";
    let y_decimal =
        "17482644437196207387910659778872952193236850502325156318830589868678978890912";
    let x_hex = BigInt::from_str_radix(x_decimal, 10)
        .unwrap()
        .to_lower_hex();
    let y_hex = BigInt::from_str_radix(y_decimal, 10)
        .unwrap()
        .to_lower_hex();
    let point_hex = format!("04{x_hex:0>64}{y_hex:0>64}");
    let r_decimal = "432420386565659656852420866390673177323";
    let s_decimal =
        "115792089237316195423570985008687907852837564279074904382605163141518161494334";

    let r = BigInt::from_str_radix(r_decimal, 10).unwrap();
    let s = BigInt::from_str_radix(s_decimal, 10).unwrap();
    let public_key = PublicKey::from_sec1_hex(point_hex, secp256k1).unwrap();
    let signature = Signature::new(r, s, secp256k1).unwrap();

    assert!(verify(&hex_to_bytes(hash_hex).unwrap(), &signature, &public_key).unwrap());
}

#[test]
fn test_sign_hash_greater_than_base_point_order() {
    // To learn the purpose of this test, see `test_match_secp256k1_fix_1063`.
    //
    // openssl doesn't support "deterministic k"(RFC 6979) ECDSA signing.
    // Uses Python package fastecdsa to generate the numbers.
    // The numbers were also verified through the C library libsecp256k1.
    //
    // ```
    // from fastecdsa.curve import secp256k1
    // from fastecdsa.ecdsa import sign
    //
    // d = 1
    // hash_hex = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
    // r, s = sign(bytes.fromhex(hash_hex), d, secp256k1, prehashed=True)
    // print(f'r: {hex(r)[2:].zfill(64)}\ns: {hex(s)[2:].zfill(64)}\n')
    // ```
    let secp256k1 = secp256k1();

    // (hash_hex, signature_hex)
    let data = [
        // order - 2
        (
            (&secp256k1.base_point_order - BigInt::from(2)).to_lower_hex(),
            concat!(
                "fbe907aac2bd7cd0ce3711f644235486367bdca4b87f19f76a7935fa00c6d169",
                "7f16095dd8cb6a4da57da25e3a3178665513e12c7b4dc52f2c212d250eef6407"
            ),
        ),
        // order - 1
        (
            (&secp256k1.base_point_order - BigInt::one()).to_lower_hex(),
            concat!(
                "0315f68838865553c4bd6fab5d27c7ebc72b94f1e2939a4f34d6954f998ef2d3",
                "2464db52707d432135c48d6f37d18ee645d7a893a5505350e57b04300098ebe9"
            ),
        ),
        // order
        (
            secp256k1.base_point_order.to_lower_hex(),
            concat!(
                "a0b37f8fba683cc68f6574cd43b39f0343a50008bf6ccea9d13231d9e7e2e1e4",
                "ee12372cf8dabd69d9b51403c23893260446a5aca818c9f55a1d5e8be63972ef"
            ),
        ),
        // order + 1
        (
            (&secp256k1.base_point_order + BigInt::one()).to_lower_hex(),
            concat!(
                "6673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e8898",
                "b3e568e9ad1f52577fedf107fda18f5ebb8e5c220badf23532bf6fbcc67fb4b8"
            ),
        ),
        // order + 2
        (
            (&secp256k1.base_point_order + BigInt::from(2)).to_lower_hex(),
            concat!(
                "56166f3a4b7d34af3bcc6c8a92a8f3c40309db9f22d7c83f8c5b87b374fd8047",
                "348ebb966e4e4c5ab15c43277b857c2844e45958f79b1e511163ca560b2ab246"
            ),
        ),
    ];
    let private_key = PrivateKey::new(BigInt::one(), secp256k1).unwrap();
    for (hash_hex, signature_hex) in data {
        let (signature, _) = sign_with_options(
            &hex_to_bytes(&hash_hex).unwrap(),
            &private_key,
            &SigningOptions {
                enforce_low_s: false,
                employ_extra_random_data: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(signature.to_p1363_hex(), signature_hex);
    }
}

#[test]
fn test_match_secp256k1_fix_1063() {
    // For details see:
    // https://github.com/trezor/trezor-firmware/issues/2085
    // https://github.com/bitcoin-core/secp256k1/issues/1063
    // https://github.com/bitcoin-core/secp256k1/pull/1064

    let secp256k1 = secp256k1();
    let hash_hex = "ffffffffffffffffffffffffffffffff20202020202020202020202020202020";
    let d_decimal =
        "22222222222222222222222222222222222222222222222222222222222222222222222222222";
    let private_key =
        PrivateKey::new(BigInt::from_str_radix(d_decimal, 10).unwrap(), secp256k1).unwrap();
    let (signature, _) = sign_with_options(
        &hex_to_bytes(&hash_hex).unwrap(),
        &private_key,
        &SigningOptions {
            enforce_low_s: true,
            employ_extra_random_data: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        signature.to_p1363_hex(),
        concat!(
            "e3d70248ea2fc771fc8d5e62d76b9cfd5402c96990333549eaadce1ae9f737eb",
            "5cfbdc7d1e0ec18cc9b57bbb18f0a57dc929ec3c4dfac9073c581705015f6a8a"
        )
    );
}

#[test]
fn test_sign_hash_bytes_padding() {
    let secp256k1 = secp256k1();

    let private_key = PrivateKey::new(BigInt::one(), secp256k1).unwrap();
    let signature_hex = concat!(
        "6673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e8898",
        "b3e568e9ad1f52577fedf107fda18f5ebb8e5c220badf23532bf6fbcc67fb4b8"
    );

    #[rustfmt::skip]
    let hash_vec = [
        // &[1_u8][..],
        &[
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1_u8,
        ][..],
        &[
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1_u8, 66,
        ][..],
    ];

    for hash in hash_vec {
        let (signature, _) = sign_with_options(
            hash,
            &private_key,
            &SigningOptions {
                enforce_low_s: false,
                strict_hash_byte_length: false,
                employ_extra_random_data: false,
                ..Default::default()
            },
        )
        .unwrap();

        let hex = signature.to_p1363_hex();
        assert_eq!(hex, signature_hex);
    }
}

#[test]
#[ignore]
fn test_valid_signing() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/ecdsa.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["valid"].as_array().unwrap();
    for value in value_vec {
        let d_hex = value["d"].as_str().unwrap();
        let m_hex = value["m"].as_str().unwrap();
        let signature_hex = value["signature"].as_str().unwrap();

        let private_key = PrivateKey::new(BigInt::from_hex(d_hex).unwrap(), secp256k1).unwrap();
        let (signature, _) = sign_with_options(
            &hex_to_bytes(m_hex).unwrap(),
            &private_key,
            &SigningOptions {
                employ_extra_random_data: false,
                is_zero_hash_allowed: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(signature.to_p1363_hex(), signature_hex);
    }
}

#[test]
fn test_invalid_signing() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/ecdsa.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["invalid"]["sign"].as_array().unwrap();
    for value in value_vec {
        let d_hex = value["d"].as_str().unwrap();
        let m_hex = value["m"].as_str().unwrap();
        let private_key = match PrivateKey::new(BigInt::from_hex(d_hex).unwrap(), secp256k1) {
            Some(x) => x,
            None => continue,
        };
        let result = sign_with_options(
            &hex_to_bytes(m_hex).unwrap(),
            &private_key,
            &SigningOptions {
                employ_extra_random_data: false,
                ..Default::default()
            },
        );
        assert_eq!(result.is_err(), true);
    }
}

#[test]
fn test_invalid_verifying() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/ecdsa.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["invalid"]["verify"].as_array().unwrap();
    for value in value_vec {
        let point_hex = value["Q"].as_str().unwrap();
        let m_hex = value["m"].as_str().unwrap();
        let signature_hex = value["signature"].as_str().unwrap();
        let enforce_low_s = value["strict"].as_bool().unwrap_or(false);
        let public_key = match PublicKey::from_sec1_hex(point_hex, secp256k1) {
            Ok(x) => x,
            Err(_) => {
                continue; // invalid public key sec1 hex
            }
        };

        let signature = match Signature::from_p1363_hex(signature_hex, secp256k1) {
            Ok(x) => x,
            Err(_) => continue,
        };
        let result = verify_with_options(
            &hex_to_bytes(m_hex).unwrap(),
            &signature,
            &public_key,
            &VerifyingOptions {
                enforce_low_s,
                ..Default::default()
            },
        );
        assert_eq!(result.is_err(), true);
    }
}
