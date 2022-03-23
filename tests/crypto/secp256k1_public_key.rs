// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::path::integration_testing_data_path;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::{secp256k1, PrivateKey};
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
        let public_key_x_hex = iter.next().unwrap();

        let private_key_n = BigInt::from_str_radix(private_key_decimal, 10);
        let public_key_x = BigInt::from_hex(public_key_x_hex).unwrap();

        let private_key = PrivateKey {
            data: private_key_n,
            curve_domain: secp256k1,
        };
        let public_key = private_key.public_key();

        assert_eq!(public_key.data.x, public_key_x);
    }
}
