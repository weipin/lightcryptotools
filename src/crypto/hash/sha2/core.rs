// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Calculates k: the smallest, non-negative solution to the equation:
// `(l + 1 + k) mod b = b - l_b`
//
// l: length of message in bits
// b: length of input block in bits (512 for SHA-256, 1024 for SHA-512)
// l_b: length of the trailing padding block in bits (binary representation of `l`, 64 for SHA-256, 128 for SHA-512)
//
// For SHA-256: `(l + 1 + k) mod 512 = 448`
// For SHA-384/SHA-512: `(l + 1 + k) mod 1024 = 896`
pub(crate) fn calculate_k(l: u64, b: u64, l_b: u64) -> u64 {
    // `(l + 1 + k) mod b = b - l_b` =>
    // `(l + 1 + k + l_b) mod b = 0`
    let k = 2 * b - (l % b + 1 + l_b);
    if k >= b {
        k - b
    } else {
        k
    }
}

// compression iteration
macro_rules! rnd {
    // ```
    // t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
    // t1 = Sigma0(a) + Maj(a, b, c);
    // d += t0;
    // h = t0 + t1;
    // ```
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $w:ident, $i:literal, $ki:literal) => {
        let t0 = $h
            .wrapping_add(sigma1($e))
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add($ki)
            .wrapping_add($w[$i]);
        let t1 = sigma0($a).wrapping_add(maj($a, $b, $c));
        $d = $d.wrapping_add(t0);
        $h = t0.wrapping_add(t1);
    };
}

pub(crate) use rnd;
