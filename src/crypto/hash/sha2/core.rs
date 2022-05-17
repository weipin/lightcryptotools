// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
