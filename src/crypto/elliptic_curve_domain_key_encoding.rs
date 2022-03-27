// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::crypto::elliptic_curve_domain::EllipticCurveDomain;
use crate::math::elliptic_curve::Point;

pub(crate) trait EllipticCurveDomainKeyEncoding {
    fn decode_point<T: AsRef<[u8]>>(
        data: T,
        curve_domain: &EllipticCurveDomain,
    ) -> Result<Point, Box<dyn std::error::Error>>;

    fn encode_point(
        point: &Point,
        curve_domain: &EllipticCurveDomain,
        compressed: bool,
    ) -> String;
}
