// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![feature(test)]

extern crate test;

use lightcryptotools::bigint::{BigInt, Digit, Sign};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use test::Bencher;

#[bench]
fn div_rem_bench(bench: &mut Bencher) {
    let mut rng = StdRng::from_entropy();
    let mut a = vec![0 as Digit; 32];
    let mut b = vec![0 as Digit; 32];

    for digit in a.iter_mut() {
        *digit = rng.gen_range(1..=Digit::MAX)
    }
    for digit in b.iter_mut() {
        *digit = rng.gen_range(1..=Digit::MAX)
    }
    let a_len = a.len();
    let b_len = b.len();

    let a = BigInt::new(a, a_len, Sign::Positive);
    let b = BigInt::new(b, b_len, Sign::Positive);
    let c = &a * &b;

    bench.iter(|| {
        let _ = &c / &b;
    })
}
