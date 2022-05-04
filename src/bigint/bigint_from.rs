// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_core::{BigInt, Sign};

macro_rules! impl_bigint_from_unsigned_int {
    ($T:ty) => {
        impl From<$T> for BigInt {
            fn from(n: $T) -> Self {
                BigInt::from_u128(n as u128, Sign::Positive)
            }
        }
    };
}

impl_bigint_from_unsigned_int!(u8);
impl_bigint_from_unsigned_int!(u16);
impl_bigint_from_unsigned_int!(u32);
impl_bigint_from_unsigned_int!(u64);
impl_bigint_from_unsigned_int!(u128);
impl_bigint_from_unsigned_int!(usize);

macro_rules! impl_bigint_from_signed_int {
    ($T:ty) => {
        impl From<$T> for BigInt {
            fn from(i: $T) -> Self {
                BigInt::from_i128(i as i128)
            }
        }
    };
}

impl_bigint_from_signed_int!(i8);
impl_bigint_from_signed_int!(i16);
impl_bigint_from_signed_int!(i32);
impl_bigint_from_signed_int!(i64);
impl_bigint_from_signed_int!(i128);
impl_bigint_from_signed_int!(isize);

#[cfg(test)]
macro_rules! test_from_int {
    ($T:ty, $fn_name:ident) => {
        #[quickcheck]
        fn $fn_name(n: $T) -> bool {
            let a = BigInt::from(n);
            n == <$T>::from_str_radix(&a.to_hex(), 16).unwrap()
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::CodecsError;
    use crate::testing_tools::quickcheck::BigIntHexString;
    use ::quickcheck_macros::quickcheck;

    #[test]
    fn test_from_hex() {
        let data = [
            ("", "00"),
            ("00", "00"),
            ("79be66", "79be66"),
            (
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
            ("-00", "00"),
            ("-79be66", "-79be66"),
            (
                "-79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "-79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
        ];
        for (a_hex, output) in data {
            let a = BigInt::from_hex(a_hex).unwrap();

            assert_eq!(a.to_hex(), output);
        }
    }

    #[quickcheck]
    fn from_hex_and_to_hex_double_conversion(hex: BigIntHexString) -> bool {
        let n1 = BigInt::from_hex(hex.0).unwrap();
        let hex = n1.to_hex();
        let n2 = BigInt::from_hex(hex).unwrap();
        n1 == n2
    }

    #[test]
    fn test_from_hex_with_errors() {
        let data = [
            ("0", CodecsError::NotByteAligned),
            ("79be661", CodecsError::NotByteAligned),
            ("-0", CodecsError::NotByteAligned),
            ("-0x79be66", CodecsError::InvalidCharFound),
        ];
        for (a_hex, err) in data {
            assert_eq!(BigInt::from_hex(a_hex).unwrap_err(), err);
        }
    }

    test_from_int!(u128, test_from_u128);
    test_from_int!(u64, test_from_u64);
    test_from_int!(u32, test_from_u32);
    test_from_int!(u16, test_from_u16);
    test_from_int!(u8, test_from_u8);

    test_from_int!(i128, test_from_i128);
    test_from_int!(i64, test_from_i64);
    test_from_int!(i32, test_from_i32);
    test_from_int!(i16, test_from_i16);
    test_from_int!(i8, test_from_i8);
}
