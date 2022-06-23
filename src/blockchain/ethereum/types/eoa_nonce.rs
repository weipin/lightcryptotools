// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt;
use std::fmt::Display;

/// Represents an EOA nonce.
///
/// nonce: ..."A scalar value equal to the number of transactions
///   sent from this address or, in the case
///   of accounts with associated code, the number of
///   contract-creations made by this account..." -- Ethereum Yellow Paper, 4.1. World State
///
/// Nonce is an unsigned integer in [0, 2^64-1).
/// See [EIP-2681: Limit account nonce to 2^64-1][1]
///
///
/// [1]: https://eips.ethereum.org/EIPS/eip-2681
pub struct EoaNonce(u64);

impl EoaNonce {
    pub fn from_u64(n: u64) -> Option<EoaNonce> {
        if n == u64::MAX {
            None
        } else {
            Some(EoaNonce(n))
        }
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for EoaNonce {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match EoaNonce::from_u64(value) {
            None => Err("out of range: nonce equals to 2^64-1"),
            Some(nonce) => Ok(nonce),
        }
    }
}

impl Display for EoaNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0;
        write!(f, "{n:#x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common() {
        assert_eq!(18446744073709551615_u64, u64::MAX);

        // 2^64-2
        assert_eq!(
            EoaNonce::from_u64(18446744073709551614_u64)
                .unwrap()
                .value(),
            18446744073709551614_u64
        );
        // 2^64-1
        assert!(EoaNonce::from_u64(18446744073709551615_u64).is_none());
    }
}
