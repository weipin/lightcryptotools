// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigInt;
use crate::crypto::elliptic_curve_domain::{
    EllipticCurveDomain, EllipticCurveDomainKeyEncoding,
};
use crate::crypto::sec1::{PointDecodingError, Sec1};
use crate::math::elliptic_curve::Point;

pub struct PrivateKey<'a> {
    pub data: BigInt,
    pub curve_domain: &'a EllipticCurveDomain,
}

#[derive(Debug, PartialEq)]
pub struct PublicKey<'a> {
    pub data: Point,
    pub curve_domain: &'a EllipticCurveDomain,
}

impl PrivateKey<'_> {
    pub fn public_key(&self) -> PublicKey {
        let curve_domain = self.curve_domain;
        let data = curve_domain
            .curve
            .mul_point(&curve_domain.base_point, &self.data);

        PublicKey { data, curve_domain }
    }
}

impl PublicKey<'_> {
    pub fn is_valid(&self) -> bool {
        self.curve_domain.validate_point(&self.data)
    }
}

impl PublicKey<'_> {
    pub fn from_sec1_hex<T: AsRef<[u8]>>(
        hex: T,
        curve_domain: &EllipticCurveDomain,
    ) -> Result<PublicKey, PointDecodingError> {
        match Sec1::decode_point(hex, curve_domain) {
            Ok(point) => Ok(PublicKey {
                data: point,
                curve_domain,
            }),
            Err(err) => Err(*err.downcast_ref::<PointDecodingError>().unwrap()),
        }
    }

    pub fn to_sec1_hex(&self, compressed: bool) -> String {
        Sec1::encode_point(&self.data, self.curve_domain, compressed)
    }
}
