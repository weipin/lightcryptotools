// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements modular arithmetic functions.

use crate::bigint::bigint_core::BigInt;
use crate::bigint::gcd::gcd;

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

/// Returns the modulo multiplicative inverse of `a` under modulo `n`.
///
/// Returns `None` if `a` is not invertible.
pub(crate) fn invert(a: &BigInt, n: &BigInt) -> Option<BigInt> {
    // // Employs the extended Euclidean algorithm:
    // // https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures
    // debug_assert!(!a.is_zero());
    // debug_assert!(n > &BigInt::one());
    //
    // let a = modulo(a, n); // ensures a > 0
    //
    // let mut t = BigInt::zero();
    // let mut newt = BigInt::one();
    // let mut r = n.clone();
    // let mut newr = a;
    //
    // while !newr.is_zero() {
    //     let quotient = &r / &newr;
    //     (newt, t) = (&t - &quotient * &newt, newt);
    //     (newr, r) = (&r - &quotient * &newr, newr);
    // }
    //
    // if r > BigInt::one() {
    //     panic!("a is not invertible");
    // }
    //
    // if t < BigInt::zero() {
    //     t = &t + n;
    // }
    // t

    // Employs extended Euclidean algorithm to compute the multiplicative inverse.
    // https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures
    debug_assert!(n > &BigInt::one());
    debug_assert!(!a.is_zero());

    let a = modulo(a, n); // ensures a > 0

    let (_, y, v) = gcd(n, &a);
    // xn + ya = 1
    if v != BigInt::one() {
        None
    } else {
        // ya = 1 mod n
        Some(y)
    }
}

/// Raises `a` to the power of `exp` under modulo `n`.
pub(crate) fn pow(a: &BigInt, exp: &BigInt, n: &BigInt) -> BigInt {
    debug_assert!(a > &BigInt::zero());
    debug_assert!(a < n);
    debug_assert!(exp >= &BigInt::zero());
    debug_assert!(n > &BigInt::zero());

    let zero = BigInt::zero();
    let mut result = BigInt::one();
    let mut exp = exp.clone();
    let mut base = a.clone();

    while exp > zero {
        if exp.is_odd() {
            result = &result * &base % n;
        }
        exp = exp >> 1;
        base = &base * &base % n;
    }

    result
}

/// Calculates the square roots of `a` under modulo `p`.
/// Returns None if no such roots exist.
///
/// It is important to note that `p` must be prime, otherwise either the execution may enter an infinite loop
/// or the result returned is incorrect.
pub(crate) fn sqrt(a: &BigInt, p: &BigInt) -> Option<(BigInt, BigInt)> {
    // Employs the Tonelli–Shanks algorithm:
    // https://www.maa.org/sites/default/files/pdf/upload_library/22/Polya/07468342.di020786.02p0470a.pdf
    //
    // TODO:
    // A non-prime `p` should not lead to an infinite loop:
    // https://www.openssl.org/news/secadv/20220315.txt
    // https://github.com/openssl/openssl/commit/3469282ed2faee747868150089e07a187891b5ee#diff-3a06cdfa864a5f8a90ea132ff6c4a544dbc196105f9c91d2d7316be4c55837d4
    //
    // a = 0x20a7ee, p = 0x460201
    // a = 1, p = 1

    let zero = BigInt::zero();
    let one = BigInt::one();
    let two = BigInt::from(2);

    assert!(p.is_odd());
    assert!(p > &two);
    assert!(a > &zero);
    assert!(a < p);

    let p_minus_1 = p - &one;

    // a ^ ((p - 1) / 2) mod p
    let t = pow(a, &(&p_minus_1 / &two), p);
    if t != one {
        // no square root
        return None;
    }

    // With p - 1 = s * 2 ^ e, finds `s` odd and `e` positive.
    let e = p_minus_1.trailing_zeros();
    let s = &p_minus_1 >> e;

    // Finds a number `n` such that n ^ ((p - 1) / 2) = -1 mod p.
    let mut n = BigInt::from(2);
    let t1 = &p_minus_1 / &two;
    let t2 = modulo(&BigInt::from(-1), p);
    while pow(&n, &t1, p) != t2 {
        n = n + &one;
    }

    let mut x = pow(a, &((&s + &one) / &two), p);
    let mut b = pow(a, &s, p);
    let mut g = pow(&n, &s, p);
    let mut r = e;

    loop {
        let mut count = 0;
        let mut t = b.clone();
        // Finds the least m that b ^ (2 ^ m) = 1 mod p
        let m = loop {
            if t == one {
                break count;
            }

            count += 1;
            if count == r {
                panic!("cannot find the least m");
            }

            // t * t = b ^ (2 ^ (m + 1))
            //
            // t * t = b ^ (2 ^ m) * b ^ (2 ^ m) =
            // b ^ ((2 ^ m) + (2 ^ m)) = b ^ (2 * (2 ^ m))
            // b ^ (2 ^ (m + 1))
            t = &t * &t % p;
        };

        if m == 0 {
            let roots = (x.clone(), modulo(&-x, p));
            return Some(roots);
        }

        x = x * pow(&g, &(BigInt::one() << (r - m - 1)), p) % p;
        b = b * pow(&g, &(BigInt::one() << (r - m)), p) % p;
        g = pow(&g, &(BigInt::one() << (r - m)), p);
        r = m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_pow() {
        // Tests the basic cases
        let three = BigInt::from(3);
        let n = BigInt::from(u64::MAX);
        for exp in 0..29 {
            let result = pow(&three, &BigInt::from(exp), &n);
            assert_eq!(result, BigInt::from(3_u64.pow(exp)));
        }

        // 78 ** 12 % 123 = 57
        let result = pow(&BigInt::from(78), &BigInt::from(12), &BigInt::from(123));
        assert_eq!(result, BigInt::from(57));
    }

    #[test]
    fn test_sqrt() {
        // (a, p, root1, root2)
        let data = [(2, 113, 62, 51), (5, 40961, 19424, 21537)];
        for (a, p, root1, root2) in data {
            let a = BigInt::from(a);
            let p = BigInt::from(p);
            let root1 = BigInt::from(root1);
            let root2 = BigInt::from(root2);

            let result = sqrt(&a, &p).unwrap();
            // compares
            assert_eq!(result.0, root1);
            assert_eq!(result.1, root2);

            // verifies
            assert_eq!(modulo(&(&root1 * &root1), &p), a);
            assert_eq!(modulo(&(&root2 * &root2), &p), a);

            // no roots
            assert_eq!(sqrt(&(a + BigInt::one()), &p), None);
        }

        // Finds square roots of 2 mod p, where
        // p = 360027784083079948259017962255826129
        let a = BigInt::from(2);
        let p = BigInt::from_str_radix("360027784083079948259017962255826129", 10);
        let (root1, _) = sqrt(&a, &p).unwrap();
        assert_eq!(
            root1,
            BigInt::from_str_radix("162244492740221711333411667492080568", 10)
        );
    }
}
