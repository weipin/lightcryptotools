// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::modular::{invert, modulo};
use crate::bigint::BigInt;

/// A curve "y^2 = x^3 + a * x + b"
/// with respect to the integers modulo `p`.
#[derive(Debug, PartialEq, Eq)]
pub struct Curve {
    pub a: BigInt,
    pub b: BigInt,
    pub p: BigInt,
}

impl Curve {
    pub(crate) fn modulo(&self, a: &BigInt) -> BigInt {
        modulo(a, &self.p)
    }

    /// Adds `a` to itself.
    fn double_point(&self, a: &Point) -> Point {
        debug_assert!(a.x >= BigInt::zero() && a.x < self.p);
        debug_assert!(a.y >= BigInt::zero() && a.y < self.p);

        if a.is_identity_element() {
            return Point::identity_element();
        }

        let two = BigInt::from(2);
        let three = BigInt::from(3);

        // m = (3 * point.x ^ 2 + a) / 2 * point.y
        let m = (&three * &a.x * &a.x + &self.a) * self.invert(&(&two * &a.y)).unwrap();
        let m = self.modulo(&m);

        // x = m^2 – 2 * point.x
        let x = &m * &m - &two * &a.x;
        let x = self.modulo(&x);

        // y = m * (point.x - x) – point.y
        let y = &m * (&a.x - &x) - &a.y;
        let y = self.modulo(&y);

        Point { x, y }
    }

    /// Adds point `a` to point `b`.
    pub(crate) fn add_points(&self, a: &Point, b: &Point) -> Point {
        debug_assert!(a.x >= BigInt::zero() && a.x < self.p);
        debug_assert!(a.y >= BigInt::zero() && a.y < self.p);
        debug_assert!(b.x >= BigInt::zero() && b.x < self.p);
        debug_assert!(b.y >= BigInt::zero() && b.y < self.p);

        // O + O = O
        if a.is_identity_element() && b.is_identity_element() {
            return Point::identity_element();
        }

        // O + b = b
        if a.is_identity_element() {
            return b.clone();
        }

        // a + O = a
        if b.is_identity_element() {
            return a.clone();
        }

        if a == b {
            return self.double_point(a);
        }

        if a.x == b.x {
            if a.y == self.modulo(&(-&b.y)) {
                // P + (–P) = O
                return Point::identity_element();
            } else {
                panic!("invalid points")
            }
        }

        // m = (b.y – a.y) / (b.x – a.x)
        let m = (&b.y - &a.y) * self.invert(&(&b.x - &a.x)).unwrap();
        let m = self.modulo(&m);

        // x = m^2 – a.x – b.x
        let x = &m * &m - &a.x - &b.x;
        let x = self.modulo(&x);

        // y = m(a.x – x) – a.y
        let y = &m * (&a.x - &x) - &a.y;
        let y = self.modulo(&y);

        Point { x, y }
    }

    /// Multiplies `point` with `n`.
    pub(crate) fn mul_point(&self, point: &Point, n: &BigInt) -> Point {
        debug_assert!(point.x >= BigInt::zero());
        debug_assert!(point.y >= BigInt::zero());
        debug_assert!(n >= &BigInt::zero());

        if n.is_zero() {
            return Point::identity_element();
        }

        // Employs the double-and-add method.
        // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
        let mut result = Point::identity_element();
        let mut base = point.clone();
        for bit in n.le_bits() {
            if bit {
                result = self.add_points(&base, &result);
            }
            base = self.double_point(&base);
        }
        result
    }

    /// Returns the modulo multiplicative inverse of `a`
    /// with respect to the integers modulo `self.p`.
    pub(crate) fn invert(&self, a: &BigInt) -> Option<BigInt> {
        invert(a, &self.p)
    }
}

/// A curve point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: BigInt,
    pub y: BigInt,
}

impl Point {
    /// Tests if the point is at infinity.
    ///
    /// For a point at infinity, we use the name "identity element".
    /// It is also named as neutral element or additive identity.
    pub(crate) fn is_identity_element(&self) -> bool {
        self.x.is_zero() && self.y.is_zero()
    }

    /// Creates a point at infinity.
    pub(crate) fn identity_element() -> Point {
        Point {
            x: BigInt::zero(),
            y: BigInt::zero(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul_point() {
        // Numbers from the book Understanding Cryptography, 9.2

        // y^2 = x^3 + 2 * x + 2 mod 17
        let curve = Curve {
            a: BigInt::from(2),
            b: BigInt::from(2),
            p: BigInt::from(17),
        };
        // P = (5, 1)
        let p = Point {
            x: BigInt::from(5),
            y: BigInt::from(1),
        };

        // (n, x, y)
        let data = [
            (1, 5, 1),
            (2, 6, 3),
            (3, 10, 6),
            (4, 3, 1),
            (5, 9, 16),
            (6, 16, 13),
            (7, 0, 6),
            (8, 13, 7),
            (9, 7, 6),
            (10, 7, 11),
            (11, 13, 10),
            (12, 0, 11),
            (13, 16, 4),
            (14, 9, 1),
            (15, 3, 16),
            (16, 10, 11),
            (17, 6, 14),
            (18, 5, 16),
            (19, 0, 0), // 19P = O
            (20, 5, 1), // 20P = 19P + P = O + P = P
        ];

        let subgroup_order = BigInt::from(19);
        for (n, x, y) in data {
            let result = curve.mul_point(&p, &BigInt::from(n));
            let point = Point {
                x: BigInt::from(x),
                y: BigInt::from(y),
            };
            assert_eq!(result, point);

            // subgroup order = 19
            // 19 * point = O
            assert_eq!(
                curve
                    .mul_point(&point, &subgroup_order)
                    .is_identity_element(),
                true
            )
        }
    }

    #[test]
    #[should_panic]
    fn test_adding_point_with_x_greater_than_p_should_panic() {
        // secp256k1 curve
        let curve = Curve {
            a: BigInt::from(0),
            b: BigInt::from(7),
            p: BigInt::from_hex(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            )
            .unwrap(),
        };

        let xs = BigInt::one();
        let xt = &curve.p + BigInt::one();
        let ys = BigInt::one();
        let point1 = Point {
            x: xs,
            y: ys.clone(),
        };
        let point2 = Point { x: xt, y: ys };
        curve.add_points(&point1, &point2);
    }
}
