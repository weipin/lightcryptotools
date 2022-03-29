// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::path::integration_testing_data_path;
use lightcryptotools::crypto::ecdsa::PublicKey;
use lightcryptotools::crypto::secp256k1;
use serde_json::Value;
use std::fs::File;

#[test]
fn test_point_to_hex_compressed() {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/points.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["valid"]["pointCompress"].as_array().unwrap();
    for value in value_vec {
        let p = value["P"].as_str().unwrap();
        let compressed = value["compress"].as_bool().unwrap();
        let expected = value["expected"].as_str().unwrap();

        let public_key = PublicKey::from_sec1_hex(p, secp256k1).unwrap();
        let hex = public_key.to_sec1_hex(compressed);
        assert_eq!(hex, expected);
    }
}
