// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigInt;
use crate::math::elliptic_curve::{Curve, Point};

pub struct EllipticCurveDomain {
    pub(crate) curve: Curve,
    pub(crate) base_point: Point,
    pub(crate) base_point_order: BigInt,
    pub(crate) cofactor: u32,
}
