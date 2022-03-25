// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::BigInt;

impl BigInt {
    pub fn from_str_radix(s: &str, radix: u8) -> BigInt {
        debug_assert!((2..=32).contains(&radix));

        fn char_to_int(c: u8) -> u8 {
            match c {
                // 0 - 9
                48..=57 => c - 48,
                // 'a' - 'z'
                97..=122 => c - 87,
                // 'A' - 'Z'
                65..=90 => c - 55,
                _ => panic!("invalid char"),
            }
        }

        let radix_bigint = BigInt::from(radix);
        let mut result = BigInt::zero();
        for n in s.bytes().map(char_to_int) {
            if n > radix {
                panic!("digit greater than the specified radix")
            }

            result = result * &radix_bigint;
            result = result + BigInt::from(n);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing_tools::quickcheck::HexString;
    use ::quickcheck_macros::quickcheck;

    #[quickcheck]
    fn from_str_radix_16_eq_from_hex(hex: HexString) -> bool {
        let a = BigInt::from_hex(&hex.0).unwrap();
        let b = BigInt::from_str_radix(&hex.0, 16);
        a == b
    }
}
