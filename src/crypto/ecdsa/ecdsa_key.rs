// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigInt;
use crate::crypto::elliptic_curve_params::{
    EllipticCurveDomainKeyEncoding, EllipticCurveParams,
};
use crate::crypto::sec1::{PointDecodingError, Sec1};
use crate::math::elliptic_curve::Point;

#[non_exhaustive]
pub struct PrivateKey<'a> {
    pub data: BigInt,
    pub curve_params: &'a EllipticCurveParams,
}

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub struct PublicKey<'a> {
    pub data: Point,
    pub curve_params: &'a EllipticCurveParams,
}

impl<'a> PrivateKey<'a> {
    pub fn new(data: BigInt, curve_params: &'a EllipticCurveParams) -> Option<Self> {
        let private_key = PrivateKey { data, curve_params };
        if private_key.is_valid() {
            Some(private_key)
        } else {
            None
        }
    }

    pub fn is_valid(&self) -> bool {
        self.data > BigInt::zero() && self.data < self.curve_params.base_point_order
    }

    pub fn public_key(&self) -> PublicKey {
        assert!(self.is_valid());

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
        if public_key.is_valid() {
            Some(public_key)
        } else {
            None
        }
    }

    pub fn is_valid(&self) -> bool {
        self.curve_params.validate_point(&self.data)
    }

    pub fn from_sec1_hex<T: AsRef<[u8]>>(
        hex: T,
        curve_params: &EllipticCurveParams,
    ) -> Result<PublicKey, PointDecodingError> {
        match Sec1::decode_point(hex, curve_params) {
            // Bypasses `PublicKey::new()`,
            // for `point` has already been validated by `decode_point`.
            Ok(point) => Ok(PublicKey {
                data: point,
                curve_params,
            }),
            Err(err) => Err(*err.downcast_ref::<PointDecodingError>().unwrap()),
        }
    }

    pub fn to_sec1_hex(&self, compressed: bool) -> String {
        Sec1::encode_point(&self.data, self.curve_params, compressed)
    }
}
