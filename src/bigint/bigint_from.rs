// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_core::BigInt;
use crate::crypto::CodecsError;

impl TryFrom<&str> for BigInt {
    type Error = CodecsError;

    fn try_from(hex: &str) -> Result<Self, Self::Error> {
        BigInt::from_hex(hex)
    }
}

impl From<u128> for BigInt {
    fn from(n: u128) -> Self {
        BigInt::from_u128(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::quickcheck_macros::quickcheck;

    #[test]
    fn test_from_hex() {
        let data = [
            ("00", "01", "01"),
            ("79be66", "483ADA7726A3C465", "483ada77271d82cb"),
            (
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
                "c1f940f620808011b3455e91dc9813afffb3b123d4537cf2f63a51eb1208ec50",
            ),
        ];
        for (a_hex, b_hex, c_hex) in data {
            let a = BigInt::try_from(a_hex).unwrap();
            let b = BigInt::try_from(b_hex).unwrap();
            let c = BigInt::try_from(c_hex).unwrap();

            assert_eq!(a + b, c)
        }
    }

    #[quickcheck]
    fn test_from_u128(n: u128) -> bool {
        let a = BigInt::from(n);
        n == u128::from_str_radix(&a.to_hex(), 16).unwrap()
    }
}
