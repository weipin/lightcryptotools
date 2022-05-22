// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::hex::random_hex;
use lightcryptotools::crypto::codecs::hex_to_bytes;
use lightcryptotools::crypto::hash::{Sha3_256, Sha3_384, Sha3_512, UnkeyedHash};
use test::Bencher;

const HASH_BYTE_LEN: usize = 1024 * 1024;

#[bench]
fn sha3_256_input_4096_bytes(bench: &mut Bencher) {
    let bytes = hex_to_bytes(random_hex(4096 * 2)).unwrap();

    bench.iter(|| {
        Sha3_256::new().digest(&bytes);
    })
}

#[bench]
fn sha3_256(bench: &mut Bencher) {
    let bytes = hex_to_bytes(random_hex(HASH_BYTE_LEN * 2)).unwrap();

    bench.iter(|| {
        Sha3_256::new().digest(&bytes);
    })
}

#[bench]
fn sha3_384(bench: &mut Bencher) {
    let bytes = hex_to_bytes(random_hex(HASH_BYTE_LEN * 2)).unwrap();

    bench.iter(|| {
        Sha3_384::new().digest(&bytes);
    })
}

#[bench]
fn sha3_512(bench: &mut Bencher) {
    let bytes = hex_to_bytes(random_hex(HASH_BYTE_LEN * 2)).unwrap();

    bench.iter(|| {
        Sha3_512::new().digest(&bytes);
    })
}
