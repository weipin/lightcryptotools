// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::hex::decimal_to_hex;
use devtools::path::integration_testing_data_path;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::{secp256k1, PrivateKey, PublicKey};
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
fn test_get_public_key_from_private_key() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/privates-2.txt");
    let file = File::open(path).unwrap();
    for line in BufReader::new(file).lines() {
        let line = line.unwrap();
        let mut iter = line.split(':');
        let private_key_decimal = iter.next().unwrap();
        let private_key_hex = decimal_to_hex(private_key_decimal);
        let public_key_x_hex = iter.next().unwrap();

        let private_key_n = BigInt::from_hex(private_key_hex).unwrap();
        let public_key_x = BigInt::from_hex(public_key_x_hex).unwrap();

        let private_key = PrivateKey {
            data: private_key_n,
            curve_domain: secp256k1,
        };
        let public_key = private_key.public_key();

        assert_eq!(public_key.data.x, public_key_x);
    }
}

#[test]
fn test_public_key_from_hex_validating() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/points.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let is_point_vec = root["valid"]["isPoint"].as_array().unwrap();
    for point_value in is_point_vec {
        let p = point_value["P"].as_str().unwrap();
        let expected = point_value["expected"].as_bool().unwrap();

        let result = PublicKey::from_sec1_hex(p, secp256k1);
        assert_eq!(result.is_ok(), expected);
    }
}

#[test]
fn test_get_public_key_from_scalar() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/points.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let point_from_scalar_vec = root["valid"]["pointFromScalar"].as_array().unwrap();
    for scalar_value in point_from_scalar_vec {
        let d = scalar_value["d"].as_str().unwrap();
        let expected = scalar_value["expected"].as_str().unwrap();

        let private_key = PrivateKey {
            data: BigInt::from_hex(d).unwrap(),
            curve_domain: secp256k1,
        };
        let public_key = private_key.public_key();
        let expected_public_key = PublicKey::from_sec1_hex(expected, secp256k1).unwrap();

        assert_eq!(public_key, expected_public_key);
    }
}
