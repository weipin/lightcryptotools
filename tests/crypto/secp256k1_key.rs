// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::path::integration_testing_data_path;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::ecdsa::{PrivateKey, PublicKey};
use lightcryptotools::crypto::secp256k1;
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
#[ignore]
fn test_private_key_validating() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/privates.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["valid"]["isPrivate"].as_array().unwrap();
    for value in value_vec {
        let d = value["d"].as_str().unwrap();
        let expected = value["expected"].as_bool().unwrap();

        let result = PrivateKey::new(BigInt::from_hex(d).unwrap(), secp256k1);
        assert_eq!(result.is_some(), expected);
    }
}

#[test]
#[ignore]
fn test_private_key_adding() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/privates.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["valid"]["privateAdd"].as_array().unwrap();
    for value in value_vec {
        let a_hex = value["d"].as_str().unwrap();
        let b_hex = value["tweak"].as_str().unwrap();
        let expected = value["expected"].as_str();

        let a = BigInt::from_hex(a_hex).unwrap();
        // Validates `a`
        let private_key_a = PrivateKey::new(a, secp256k1).unwrap();
        let b = BigInt::from_hex(b_hex).unwrap();
        let c = (private_key_a.data + b) % &secp256k1.base_point_order;
        match PrivateKey::new(c, secp256k1) {
            Some(private_key) => {
                let hex = private_key.data.to_lower_hex();
                assert_eq!(format!("{hex:0>64}"), expected.unwrap());
            }
            None => {
                assert!(expected.is_none());
            }
        }
    }
}

#[test]
#[ignore]
fn test_private_key_negating() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/privates.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["valid"]["negate"].as_array().unwrap();
    for value in value_vec {
        let a_hex = value["a"].as_str().unwrap();
        let expected = value["expected"].as_str().unwrap();

        let a = BigInt::from_hex(a_hex).unwrap();
        let b = &secp256k1.base_point_order - a;
        let hex = b.to_lower_hex();
        assert_eq!(format!("{hex:0>64}"), expected);
    }
}

#[test]
fn test_get_public_key_from_private_key() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/privates-2.txt");
    let file = File::open(path).unwrap();
    for line in BufReader::new(file).lines() {
        let line = line.unwrap();
        let mut iter = line.split(':');
        let private_key_decimal = iter.next().unwrap();
        let public_key_x_hex = iter.next().unwrap();

        let private_key_n = BigInt::from_str_radix(private_key_decimal, 10).unwrap();
        let public_key_x = BigInt::from_hex(public_key_x_hex).unwrap();

        let private_key = PrivateKey::new(private_key_n, secp256k1).unwrap();
        let public_key = private_key.public_key();

        assert_eq!(public_key.data.x, public_key_x);
    }
}

#[test]
fn test_public_key_from_sec1_hex_validating() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/points.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["valid"]["isPoint"].as_array().unwrap();
    for value in value_vec {
        let p = value["P"].as_str().unwrap();
        let expected = value["expected"].as_bool().unwrap();

        let result = PublicKey::from_sec1_hex(p, secp256k1);
        assert_eq!(result.is_ok(), expected);
    }
}

#[test]
fn test_point_from_scalar() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/points.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["valid"]["pointFromScalar"].as_array().unwrap();
    for value in value_vec {
        let d = value["d"].as_str().unwrap();
        let expected = value["expected"].as_str().unwrap();

        let private_key = PrivateKey::new(BigInt::from_hex(d).unwrap(), secp256k1).unwrap();
        let public_key = private_key.public_key();
        let expected_public_key = PublicKey::from_sec1_hex(expected, secp256k1).unwrap();

        assert_eq!(public_key, expected_public_key);
    }
}
