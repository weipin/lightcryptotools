// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements modular arithmetic functions.

use crate::bigint::BigInt;

/// Calculates `a` modulo `n`,
/// returning the least non-negative remainder of `a (mod n)`.
///
/// Will panic if `n <= 0`.
pub(crate) fn modulo(a: &BigInt, n: &BigInt) -> BigInt {
    debug_assert!(n > &BigInt::zero());

    let r = a % n;
    if r < BigInt::zero() {
        r + n
    } else {
        r
    }
}

#[cfg(test)]
mod tests {
    use crate::bigint::modular::modulo;
    use crate::bigint::BigInt;

    #[test]
    fn test_modulo() {
        let data = [(6, 1, 0), (1, 2, 1), (-7, 2, 1), (-2, 7, 5), (-1, 1, 0)];
        for (a, b, result) in data {
            let a = BigInt::from(a);
            let b = BigInt::from(b);
            let c = modulo(&a, &b);
            assert_eq!(c, BigInt::from(result));
        }
    }
}
