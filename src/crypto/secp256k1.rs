// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::elliptic_curve_domain::EllipticCurveDomain;
use crate::bigint::BigInt;
use crate::math::elliptic_curve::{Curve, Point};
use std::sync::Once;

static mut SECP256K1: Option<EllipticCurveDomain> = None;
static INIT: Once = Once::new();

pub fn secp256k1() -> &'static EllipticCurveDomain {
    INIT.call_once(|| unsafe {
        let domain = EllipticCurveDomain {
            curve: Curve {
                a: BigInt::from(0),
                b: BigInt::from(7),
                p: BigInt::from_hex(
                    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                )
                .unwrap(),
            },
            base_point: Point {
                x: BigInt::from_hex(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                )
                .unwrap(),
                y: BigInt::from_hex(
                    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
                )
                .unwrap(),
            },
            base_point_order: BigInt::from_hex(
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            )
            .unwrap(),
            cofactor: 1,
            name: "secp256k1",
        };
        SECP256K1 = Some(domain);
    });

    let domain = unsafe { SECP256K1.as_ref().unwrap() };
    domain
}
