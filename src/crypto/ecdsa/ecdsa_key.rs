// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigInt;
use crate::crypto::elliptic_curve_params::EllipticCurveParams;
use crate::math::elliptic_curve::Point;

pub struct PrivateKey<'a> {
    pub data: BigInt,
    pub curve_params: &'a EllipticCurveParams,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey<'a> {
    pub data: Point,
    pub curve_params: &'a EllipticCurveParams,
}

impl<'a> PrivateKey<'a> {
    pub fn new(data: BigInt, curve_params: &'a EllipticCurveParams) -> Option<Self> {
        let private_key = PrivateKey { data, curve_params };
        private_key.is_valid().then_some(private_key)
    }

    fn is_valid(&self) -> bool {
        self.data > BigInt::zero() && self.data < self.curve_params.base_point_order
    }

    pub fn public_key(&self) -> PublicKey {
        let curve_params = self.curve_params;
        let data = curve_params
            .curve
            .mul_point(&curve_params.base_point, &self.data);

        PublicKey::new(data, curve_params).unwrap()
    }
}

impl<'a> PublicKey<'a> {
    pub fn new(data: Point, curve_params: &'a EllipticCurveParams) -> Option<Self> {
        let public_key = PublicKey { data, curve_params };
        public_key.is_valid().then_some(public_key)
    }

    fn is_valid(&self) -> bool {
        self.curve_params.validate_point(&self.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keys_partial_eq() {
        let curve1 = EllipticCurveParams {
            base_point_order: BigInt::from(10),
            ..Default::default()
        };
        let curve2 = EllipticCurveParams {
            base_point_order: BigInt::from(10),
            ..Default::default()
        };
        let curve3 = EllipticCurveParams {
            base_point_order: BigInt::from(17),
            ..Default::default()
        };

        let point = Point {
            x: BigInt::from(11),
            y: BigInt::from(17),
        };
        assert_eq!(
            PublicKey {
                data: point.clone(),
                curve_params: &curve1
            },
            PublicKey {
                data: point.clone(),
                curve_params: &curve2
            }
        );
        assert_ne!(
            PublicKey {
                data: point.clone(),
                curve_params: &curve1
            },
            PublicKey {
                data: point.clone(),
                curve_params: &curve3
            }
        );
    }
}
