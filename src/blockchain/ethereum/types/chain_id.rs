// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigUint;
use std::fmt;
use std::fmt::Display;

/// Represents Chain ID
#[derive(Debug, PartialEq)]
pub struct ChainId(pub(crate) BigUint);

impl From<BigUint> for ChainId {
    fn from(n: BigUint) -> Self {
        ChainId(n)
    }
}

impl From<u64> for ChainId {
    fn from(n: u64) -> Self {
        ChainId(BigUint::from(n))
    }
}

impl Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u64)]
pub enum Chain {
    EthereumMainnet = 1,
    ExpanseMainnet = 2,
    Ropsten = 3,
    Rinkeby = 4,
    Goerli = 5,
    Kovan = 42,
    GethPrivateChains = 1337,
}

impl Chain {
    pub fn id(&self) -> ChainId {
        ChainId(BigUint::from(*self as u64))
    }
}
