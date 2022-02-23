// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![feature(test)]

extern crate test;

use lightcryptotools::bigint::BigInt;
use quickcheck::Gen;
use std::str::from_utf8;
use test::Bencher;

fn random_hex(n: usize) -> String {
    const HEX_CHARS_BYTES: &[u8] = "0123456789abcdefABCDEF".as_bytes();

    let mut gen = Gen::new(0);
    let mut chars = vec![0_u8; n];
    for c in chars.iter_mut() {
        *c = *gen.choose(HEX_CHARS_BYTES).unwrap();
    }

    String::from(from_utf8(&chars).unwrap())
}

fn div_rem_bench_bits(bench: &mut Bencher, bits: usize) {
    // 4 bits -> 1 hex digit
    let hex_len = bits >> 2;

    // len * 2 for dividend
    let a = BigInt::try_from(random_hex(hex_len << 1).as_str()).unwrap();
    let b = BigInt::try_from(random_hex(hex_len).as_str()).unwrap();

    bench.iter(|| {
        let _ = &a / &b;
    })
}

#[bench]
fn div_rem_bench_256(b: &mut Bencher) {
    div_rem_bench_bits(b, 256);
}

#[bench]
fn div_rem_bench_512(b: &mut Bencher) {
    div_rem_bench_bits(b, 512);
}

#[bench]
fn div_rem_bench_1024(b: &mut Bencher) {
    div_rem_bench_bits(b, 1024);
}

#[bench]
fn div_rem_bench_2048(b: &mut Bencher) {
    div_rem_bench_bits(b, 2048);
}
