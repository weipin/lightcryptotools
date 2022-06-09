// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_core::{BigInt, Sign};
use std::ops::Neg;

impl Neg for Sign {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        let sign = match self {
            Sign::Positive => Sign::Negative,
            Sign::Negative => Sign::Positive,
        };

        self = sign;
        self
    }
}

impl<'a> Neg for &'a Sign {
    type Output = Sign;

    fn neg(self) -> Self::Output {
        -*self
    }
}

impl Neg for BigInt {
    type Output = Self;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.sign = -self.sign;
        self
    }
}

impl<'a> Neg for &'a BigInt {
    type Output = BigInt;

    #[inline]
    fn neg(self) -> Self::Output {
        -self.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::bigint::BigInt;

    #[test]
    fn test_neg() {
        let a = -BigInt::from(17);
        assert_eq!(a.to_lower_hex(), "-11");
    }
}
