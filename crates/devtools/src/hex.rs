// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::borrow::Cow;
use std::str::from_utf8;
use quickcheck::Gen;

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

pub fn byte_aligned_hex(hex: &str) -> Cow<str> {
    if hex.len() & 1 == 0 {
        hex.into()
    } else {
        let mut t = String::with_capacity(hex.len() + 1);
        t.push('0');
        t.push_str(hex);
        t.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_aligned_hex() {
        let data = [
            ("00", "00"),
            ("1", "01"),
            ("zzz", "0zzz"),
            ("zz", "zz"),
        ];

        for (s1, s2) in data {
            assert_eq!(byte_aligned_hex(s1), s2);
        }
    }
}
