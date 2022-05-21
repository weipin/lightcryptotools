// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::path::integration_testing_data_path;
use lightcryptotools::crypto::codecs::{bytes_to_hex, hex_to_bytes};
use lightcryptotools::crypto::hash::{
    hmac, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha512, UnkeyedHash,
};
use serde_json::Value;
use std::fs::File;

#[test]
#[ignore]
fn test_hmac_wycheproof() {
    test_hmac_wycheproof_core("hmac_sha256_test.json", &mut Sha256::new());
    test_hmac_wycheproof_core("hmac_sha384_test.json", &mut Sha384::new());
    test_hmac_wycheproof_core("hmac_sha512_test.json", &mut Sha512::new());
    test_hmac_wycheproof_core("hmac_sha3_224_test.json", &mut Sha3_224::new());
    test_hmac_wycheproof_core("hmac_sha3_256_test.json", &mut Sha3_256::new());
    test_hmac_wycheproof_core("hmac_sha3_384_test.json", &mut Sha3_384::new());
    test_hmac_wycheproof_core("hmac_sha3_512_test.json", &mut Sha3_512::new());
}

fn test_hmac_wycheproof_core<T: UnkeyedHash>(data_filename: &str, hasher: &mut T) {
    let path = integration_testing_data_path(&format!("crypto/wycheproof/{data_filename}"));
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();

    let group_vec = root["testGroups"].as_array().unwrap();
    for group in group_vec {
        let tag_size = group["tagSize"].as_u64().unwrap();
        let tag_bytes = tag_size / 8;
        let value_vec = group["tests"].as_array().unwrap();
        for value in value_vec {
            let key_hex = value["key"].as_str().unwrap();
            let msg_hex = value["msg"].as_str().unwrap();
            let tag_hex = value["tag"].as_str().unwrap();
            let result_str = value["result"].as_str().unwrap();

            let digest = hmac(
                hex_to_bytes(key_hex).unwrap(),
                hex_to_bytes(msg_hex).unwrap(),
                hasher,
            );
            if bytes_to_hex(&digest[..tag_bytes as usize]) == tag_hex {
                assert_eq!(result_str, "valid");
            } else {
                assert_eq!(result_str, "invalid");
            }
        } // tests
    } // group_vec
}
