// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::crypto::ecdsa::{PublicKey, Signature};
use crate::crypto::elliptic_curve_params::EllipticCurveParamsEncoding;
use crate::crypto::p1363::P1363;
use crate::crypto::sec1::Sec1;
use crate::crypto::{p1363, sec1, EllipticCurveParams};

pub(crate) trait SignatureEncoding {
    fn decode<T: AsRef<[u8]>>(
        data: T,
        curve_params: &EllipticCurveParams,
    ) -> Result<Signature, Box<dyn std::error::Error>>;

    fn encode(signature: &Signature) -> String;
}

impl<'a> Signature<'a> {
    /// Restores a IEEE P1363 encoded signature.
    pub fn from_p1363_hex<T: AsRef<[u8]>>(
        hex: T,
        curve_params: &'a EllipticCurveParams,
    ) -> Result<Signature, p1363::SignatureDecodingError> {
        P1363::decode(hex, curve_params)
            .map_err(|e| *e.downcast_ref::<p1363::SignatureDecodingError>().unwrap())
    }

    /// Returns IEEE P1363 encoded signature.
    pub fn to_p1363_hex(&self) -> String {
        P1363::encode(self)
    }
}

impl<'a> PublicKey<'a> {
    /// Restores a `PublicKey` from SEC1 encoded elliptic curve point.
    pub fn from_sec1_hex<T: AsRef<[u8]>>(
        hex: T,
        curve_params: &EllipticCurveParams,
    ) -> Result<PublicKey, sec1::PointDecodingError> {
        match Sec1::decode_point(hex, curve_params) {
            // Bypasses `PublicKey::new()`,
            // for `point` has already been validated by `decode_point`.
            Ok(point) => Ok(PublicKey {
                data: point,
                curve_params,
            }),
            Err(err) => Err(*err.downcast_ref::<sec1::PointDecodingError>().unwrap()),
        }
    }

    /// Returns SEC1 encoded elliptic curve point.
    pub fn to_sec1_hex(&self, compressed: bool) -> String {
        Sec1::encode_point(&self.data, self.curve_params, compressed)
    }
}
