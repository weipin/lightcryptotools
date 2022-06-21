// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::path::integration_testing_data_path;
use lightcryptotools::blockchain::ethereum::account::{EoaPrivateKey, EoaPrivateKeyData};
use lightcryptotools::crypto::codecs::hex_to_bytes;
use serde_json::Value;
use std::fs::File;

#[test]
#[ignore]
fn test_eoa_private_key_to_address() {
    let path = integration_testing_data_path("blockchain/ethereum/ethers.js/accounts.json");
    let file = File::open(path).unwrap();
    let value_vec: Vec<Value> = serde_json::from_reader(file).unwrap();

    let mut count = 0;
    for value in value_vec {
        let private_key_hex_with_prefix = value["privateKey"].as_str();
        if private_key_hex_with_prefix.is_none() {
            continue;
        }
        let checksummed_address = value["checksumAddress"].as_str().unwrap();

        let key_bytes = hex_to_bytes(&private_key_hex_with_prefix.unwrap()[2..]).unwrap();
        let key_data: EoaPrivateKeyData = key_bytes.try_into().unwrap();
        let eoa_private_key = EoaPrivateKey::new(key_data).unwrap();
        let eoa_public_key = eoa_private_key.public_key();
        let address = eoa_public_key.address();
        assert_eq!(format!("{address}"), checksummed_address);

        count += 1;
    }

    assert!(count > 1000); // Ensures that we indeed have enough cases tested
}
