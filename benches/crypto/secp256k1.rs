// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::hex::random_hex;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::codecs::hex_to_bytes;
use lightcryptotools::crypto::ecdsa;
use lightcryptotools::crypto::ecdsa::SigningOptions;
use lightcryptotools::crypto::secp256k1;
use test::Bencher;

#[bench]
fn secp256k1_signing_and_verifying(bench: &mut Bencher) {
    let secp256k1 = secp256k1();

    let d_bytes_len = 32;
    let n = BigInt::from_hex(random_hex(d_bytes_len * 2).as_str()).unwrap();
    let private_key = ecdsa::PrivateKey::new(n, secp256k1).unwrap();
    let public_key = private_key.public_key();

    let hash_bytes_len = 32;
    let hash_bytes = hex_to_bytes(random_hex(hash_bytes_len * 2)).unwrap();

    bench.iter(|| {
        let (signature, _) = ecdsa::sign_with_options(
            &hash_bytes,
            &private_key,
            &SigningOptions {
                employ_extra_random_data: false,
                ..Default::default()
            },
        )
        .unwrap();
        let result = ecdsa::verify(&hash_bytes, &signature, &public_key).unwrap();
        assert_eq!(result, true);
    })
}
