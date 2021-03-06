// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigInt;
use crate::math::elliptic_curve::{Curve, Point};

#[derive(Debug, PartialEq, Eq)]
pub struct EllipticCurveParams {
    pub curve: Curve,
    pub base_point: Point,
    pub base_point_order: BigInt,
    pub cofactor: u32,
}

impl Default for EllipticCurveParams {
    fn default() -> Self {
        Self {
            curve: Curve {
                a: BigInt::zero(),
                b: BigInt::zero(),
                p: BigInt::zero(),
            },
            base_point: Point::identity_element(),
            base_point_order: BigInt::zero(),
            cofactor: 1,
        }
    }
}

pub(crate) trait EllipticCurveParamsEncoding {
    fn decode_point<T: AsRef<[u8]>>(
        data: T,
        curve_params: &EllipticCurveParams,
    ) -> Result<Point, Box<dyn std::error::Error>>;

    fn encode_point(
        point: &Point,
        curve_params: &EllipticCurveParams,
        compressed: bool,
    ) -> String;
}

impl EllipticCurveParams {
    /// Validates that `point` is legitimate in the curve.
    pub(crate) fn validate_point(&self, point: &Point) -> bool {
        // For details see "An Illustrated Guide to Elliptic Curve Cryptography Validation"
        // https://research.nccgroup.com/2021/11/18/an-illustrated-guide-to-elliptic-curve-cryptography-validation/

        let zero = BigInt::zero();
        if point.x < zero || point.y < zero {
            return false;
        }

        // Checks that the point coordinates are lower than the field modulus.
        if point.x >= self.curve.p || point.y >= self.curve.p {
            return false;
        }

        // Checks that the coordinates correspond to a valid curve point.
        // y^2 = x^3 + a * x + b
        let left = &point.y * &point.y;
        let left = self.curve.modulo(&left);
        let right = &point.x * &point.x * &point.x + &self.curve.a * &point.x + &self.curve.b;
        let right = self.curve.modulo(&right);
        if left != right {
            return false;
        }

        // Checks that the point is not the point at infinity.
        if point.is_identity_element() {
            return false;
        }

        // Checks that the point is in the correct subgroup.
        if self.cofactor != 1 {
            let np = self.curve.mul_point(point, &self.base_point_order);
            if !np.is_identity_element() {
                return false;
            }
        }

        true
    }

    // Concatenates x and y in byte representation.
    // Both x and y are leading zero padded to the length of base point order in bytes.
    pub(crate) fn point_to_bytes(&self, point: &Point) -> Vec<u8> {
        let element_byte_length = self.base_point_order.byte_len();
        let mut data = Vec::with_capacity(element_byte_length * 2);

        let bytes = point.x.to_be_bytes();
        data.extend(&vec![0; element_byte_length - bytes.len()]);
        data.extend(&bytes);

        let bytes = point.y.to_be_bytes();
        data.extend(&vec![0; element_byte_length - bytes.len()]);
        data.extend(&bytes);

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::elliptic_curve::Curve;

    #[test]
    fn test_validate_point() {
        // y^2 = x^3 + 2 * x + 2 mod 17
        let curve_params = EllipticCurveParams {
            curve: Curve {
                a: BigInt::from(2),
                b: BigInt::from(2),
                p: BigInt::from(17),
            },
            base_point: Point {
                x: BigInt::from(5),
                y: BigInt::from(1),
            },
            base_point_order: BigInt::from(19),
            cofactor: 1,
        };

        // Fakes a cofactor != 1 to test subgroup validating.
        let curve_params2 = EllipticCurveParams {
            curve: Curve {
                a: BigInt::from(2),
                b: BigInt::from(2),
                p: BigInt::from(17),
            },
            base_point: Point {
                x: BigInt::from(5),
                y: BigInt::from(1),
            },
            base_point_order: BigInt::from(19),
            cofactor: 2,
        };

        // (x, y, is_validate)
        let data = [
            (-1, 2, false), // negative
            (1, -2, false),
            (21, 2, false), // greater than the field modulus
            (2, 21, false),
            (17, 2, false),
            (2, 17, false),
            (1, 2, false), // not valid curve point
            (0, 0, false), // is at infinity
            (10, 11, true),
        ];

        for (x, y, is_validate) in data {
            let point = Point {
                x: BigInt::from(x),
                y: BigInt::from(y),
            };
            assert_eq!(curve_params.validate_point(&point), is_validate);
            assert_eq!(curve_params2.validate_point(&point), is_validate);
        }
    }
}
