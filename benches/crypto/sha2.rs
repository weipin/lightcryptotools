// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::hex::random_hex;
use lightcryptotools::crypto::codecs::hex_to_bytes;
use lightcryptotools::crypto::hash::{Sha256, Sha384, Sha512, UnkeyedHash};
use test::Bencher;

const HASH_BYTE_LEN: usize = 4096;

#[bench]
fn sha256(bench: &mut Bencher) {
    let bytes = hex_to_bytes(random_hex(HASH_BYTE_LEN * 2)).unwrap();

    bench.iter(|| {
        Sha256::new().digest(&bytes);
    })
}

#[bench]
fn sha384(bench: &mut Bencher) {
    let bytes = hex_to_bytes(random_hex(HASH_BYTE_LEN * 2)).unwrap();

    bench.iter(|| {
        Sha384::new().digest(&bytes);
    })
}

#[bench]
fn sha512(bench: &mut Bencher) {
    let bytes = hex_to_bytes(random_hex(HASH_BYTE_LEN * 2)).unwrap();

    bench.iter(|| {
        Sha512::new().digest(&bytes);
    })
}
