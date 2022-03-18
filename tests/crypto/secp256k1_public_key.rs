// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::path::integration_testing_data_path;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::{public_key_from_private_key, secp256k1};
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
fn test_get_public_key_from_private_key() {
    let secp256k1 = secp256k1();

    // The file "secp256k1/noble-secp256k1-privates-2.txt" is adapted from noble-secp256k1:
    // https://github.com/paulmillr/noble-secp256k1/blob/main/test/vectors/privates-2.txt
    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1-privates-2.txt");
    let file = File::open(path).unwrap();
    for line in BufReader::new(file).lines() {
        let line = line.unwrap();
        let mut iter = line.split(':');
        let private_key_decimal = iter.next().unwrap();
        let public_key_x_hex = iter.next().unwrap();

        let private_key = BigInt::from_str_radix(private_key_decimal, 10);
        let public_key_x = BigInt::from_hex(public_key_x_hex).unwrap();

        let point = public_key_from_private_key(&private_key, &secp256k1);

        assert_eq!(point.x, public_key_x);
    }
}
