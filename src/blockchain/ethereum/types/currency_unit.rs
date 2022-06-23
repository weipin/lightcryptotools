// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_new::ParseIntError;
use crate::bigint::BigUint;
use std::fmt;
use std::fmt::Display;

/// Represents currency unit Wei.
///
/// ...The smallest subdenomination
/// of Ether, and thus the one in which all integer values of
/// the currency are counted, is the Wei. One Ether is defined
/// as being 10^18 Wei... -- [Ethereum Yellow Paper][1], 2.1. Value
///
/// [1]: https://github.com/ethereum/yellowpaper
#[derive(Debug, PartialEq)]
pub struct Wei(pub(crate) BigUint);

impl Wei {
    /// Creates a `Wei` from hexadecimal representation `hex`.
    /// `hex` must be 1-byte aligned -- having an even number of digits.
    /// The sign prefix '-' is not allowed.
    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Wei, ParseIntError> {
        BigUint::from_hex(hex).map(|n| Ok(Wei(n)))?
    }

    /// Creates a `Wei` from a decimal string.
    pub fn from_decimal<T: AsRef<[u8]>>(s: T) -> Result<Wei, ParseIntError> {
        BigUint::from_str_radix(s, 10).map(|n| Ok(Wei(n)))?
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes()
    }
}

impl From<BigUint> for Wei {
    fn from(n: BigUint) -> Self {
        Wei(n)
    }
}

impl TryFrom<&str> for Wei {
    type Error = ParseIntError;

    fn try_from(s: &str) -> Result<Wei, ParseIntError> {
        let n = s.try_into()?;
        Ok(Wei(n))
    }
}

impl Display for Wei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.0.to_lower_hex();
        write!(f, "0x{hex}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wei_try_from_str() {
        let w1: Wei = "0x12ef".try_into().unwrap();
        let w2: Wei = "4847".try_into().unwrap();
        assert_eq!(w1, w2);
    }
}
