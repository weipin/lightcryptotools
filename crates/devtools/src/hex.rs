// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use quickcheck::Gen;
use std::str::from_utf8;

/// Returns a random string with `n` hexadecimal digits.
pub fn random_hex(n: usize) -> String {
    const HEX_CHARS_BYTES: &[u8] = "0123456789abcdef".as_bytes();

    let mut gen = Gen::new(0);
    let mut chars = vec![0_u8; n];
    for c in chars.iter_mut() {
        *c = *gen.choose(HEX_CHARS_BYTES).unwrap();
    }

    String::from(from_utf8(&chars).unwrap())
}