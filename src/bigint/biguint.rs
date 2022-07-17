// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_core::{BigInt, Sign};
use crate::bigint::bigint_new::ParseIntError;
use std::fmt;
use std::fmt::Display;
use std::ops::{Add, Mul, Shr, Sub};

#[derive(Debug, PartialEq, Eq, PartialOrd)]
pub struct BigUint(BigInt);

macro_rules! impl_biguint_from_unsigned_int {
    ($T:ty) => {
        impl From<$T> for BigUint {
            fn from(n: $T) -> Self {
                BigUint(BigInt::from_u128(n as u128, Sign::Positive))
            }
        }
    };
}

impl_biguint_from_unsigned_int!(u8);
impl_biguint_from_unsigned_int!(u16);
impl_biguint_from_unsigned_int!(u32);
impl_biguint_from_unsigned_int!(u64);
impl_biguint_from_unsigned_int!(u128);
impl_biguint_from_unsigned_int!(usize);

impl BigUint {
    pub(crate) fn from_be_bytes(bytes: &[u8]) -> BigUint {
        BigUint(BigInt::from_be_bytes(bytes, Sign::Positive))
    }

    pub(crate) fn from_bigint(n: BigInt) -> Option<BigUint> {
        if n.is_sign_negative() {
            None
        } else {
            Some(BigUint(n))
        }
    }

    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<BigUint, ParseIntError> {
        let n = BigInt::from_hex(hex)?;
        if n.is_sign_negative() {
            Err(ParseIntError::InvalidInput)
        } else {
            Ok(BigUint(n))
        }
    }

    pub fn from_str_radix<T: AsRef<[u8]>>(s: T, radix: u8) -> Result<BigUint, ParseIntError> {
        BigInt::from_str_radix(s, radix).map(|n| Ok(BigUint(n)))?
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes()
    }

    pub fn to_lower_hex(&self) -> String {
        self.0.to_lower_hex()
    }
}

/// Creates a `BigUint` from hex or decimal string.
///
/// The prefix "0x" must present for hex.
/// Sign prefixes '+' and '-' are not allowed.
///
/// ```text
/// let n1: BigUint = "0x12ef".try_into().unwrap();
/// let n2: BigUint = "4847".try_into().unwrap();
/// assert_eq!(n1, n2);
/// ```
impl TryFrom<&str> for BigUint {
    type Error = ParseIntError;

    fn try_from(s: &str) -> Result<BigUint, ParseIntError> {
        if let Some(s) = s.strip_prefix("0x") {
            BigUint::from_hex(s)
        } else {
            BigUint::from_str_radix(s, 10)
        }
    }
}

impl Add for BigUint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self((&self.0).add(&rhs.0))
    }
}

impl<'a> Sub<BigUint> for &'a BigUint {
    type Output = BigUint;

    fn sub(self, rhs: BigUint) -> Self::Output {
        BigUint((&self.0).sub(&rhs.0))
    }
}

impl Sub for BigUint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        BigUint((&self.0).sub(&rhs.0))
    }
}

impl<'a> Mul<BigUint> for &'a BigUint {
    type Output = BigUint;

    fn mul(self, rhs: BigUint) -> Self::Output {
        BigUint((&self.0).mul(&rhs.0))
    }
}

impl Mul for BigUint {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        BigUint((&self.0).mul(&rhs.0))
    }
}

impl Shr<usize> for BigUint {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        BigUint((&self.0).shr(rhs))
    }
}

impl Display for BigUint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_str() {
        let n1: BigUint = "0x12ef".try_into().unwrap();
        let n2: BigUint = "4847".try_into().unwrap();
        assert_eq!(n1, n2);
    }
}
