// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::BigInt;
use crate::crypto::elliptic_curve_domain::EllipticCurveDomain;
use crate::crypto::elliptic_curve_domain_key_encoding::EllipticCurveDomainKeyEncoding;
use crate::math::elliptic_curve::Point;
use crate::math::modular::{modulo, sqrt};
use std::fmt::{Display, Formatter};

pub(crate) struct Sec1;

#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum PointDecodingError {
    InvalidFormat,
    InvalidX,
    InvalidY,
    YNotFound,
    InvalidPoint,
}

impl Display for PointDecodingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PointDecodingError::InvalidFormat => write!(f, "Invalid format"),
            PointDecodingError::InvalidX => write!(f, "Invalid x"),
            PointDecodingError::InvalidY => write!(f, "Invalid y"),
            PointDecodingError::YNotFound => write!(f, "Y not found"),
            PointDecodingError::InvalidPoint => write!(f, "Invalid point"),
        }
    }
}

impl std::error::Error for PointDecodingError {}

impl EllipticCurveDomainKeyEncoding for Sec1 {
    /// Decodes a public key as described in http://www.secg.org/SEC1-Ver-1.0.pdf,
    /// sections 2.3.3/2.3.4.
    ///
    /// uncompressed: '4' + x + y
    /// compressed:   '2'|'3' + x
    fn decode_point<T: AsRef<[u8]>>(
        data: T,
        curve_domain: &EllipticCurveDomain,
    ) -> Result<Point, Box<dyn std::error::Error>> {
        let hex_bytes = data.as_ref();
        let point_element_hex_len = curve_domain.base_point_order.to_be_bytes().len() * 2;

        if hex_bytes.len() < point_element_hex_len + 2 {
            return Err(Box::new(PointDecodingError::InvalidFormat));
        }

        let prefix = &hex_bytes[..2];
        if prefix == b"04" {
            // uncompressed
            if hex_bytes.len() != point_element_hex_len * 2 + 2 {
                return Err(Box::new(PointDecodingError::InvalidFormat));
            }
            let x_hex_bytes = &hex_bytes[2..point_element_hex_len + 2];
            let x = match BigInt::from_hex(x_hex_bytes) {
                Ok(x) => x,
                Err(_) => {
                    return Err(Box::new(PointDecodingError::InvalidX));
                }
            };
            let y_hex_bytes = &hex_bytes[point_element_hex_len + 2..];
            let y = match BigInt::from_hex(&y_hex_bytes) {
                Ok(y) => y,
                Err(_) => {
                    return Err(Box::new(PointDecodingError::InvalidY));
                }
            };

            let point = Point { x, y };
            if !curve_domain.validate_point(&point) {
                return Err(Box::new(PointDecodingError::InvalidPoint));
            }

            return Ok(point);
        }

        if prefix != b"02" && prefix != b"03" {
            return Err(Box::new(PointDecodingError::InvalidFormat));
        }

        // compressed
        let x_hex_bytes = &hex_bytes[2..];
        let x = match BigInt::from_hex(x_hex_bytes) {
            Ok(x) => x,
            Err(_) => {
                return Err(Box::new(PointDecodingError::InvalidX));
            }
        };

        // y^2 = x^3 + a * x + b
        let y_square = &x * &x * &x + &curve_domain.curve.a * &x + &curve_domain.curve.b;
        let y_square = modulo(&y_square, &curve_domain.curve.p);

        let (root1, root2) = match sqrt(&y_square, &curve_domain.curve.p) {
            Some(roots) => roots,
            None => {
                return Err(Box::new(PointDecodingError::YNotFound));
            }
        };

        let y = if prefix == b"02" {
            // even root
            if root1.is_even() {
                root1
            } else {
                root2
            }
        } else {
            // odd root
            if root1.is_odd() {
                root1
            } else {
                root2
            }
        };

        let point = Point { x, y };
        if !curve_domain.validate_point(&point) {
            return Err(Box::new(PointDecodingError::InvalidPoint));
        }

        Ok(point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1;

    #[test]
    fn test_point_from_valid_hex() {
        // Uses Python package fastecdsa to obtain the testings numbers:
        // https://github.com/AntonKueltz/fastecdsa
        //
        // ```
        // from fastecdsa import keys, curve
        // from fastecdsa.util import mod_sqrt
        //
        // _, public_key = keys.gen_keypair(curve.secp256k1)
        // y_square = curve.secp256k1.evaluate(public_key.x)
        // (root1, root2) = mod_sqrt(y_square, curve.secp256k1.p)
        // print(f'x: {hex(public_key.x)}\ny1: {hex(root1)}\ny2: {hex(root2)}')
        // ```
        let secp256k1 = secp256k1();
        // (hex, point)
        let data = [
            // uncompressed with even y
            (
                concat!(
                    "04",
                    "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8",
                    "7561967ae7e35552012b5778030b36a39b62dfe899bb9edbbc57344e94f22db0"
                ),
                Point {
                    x: BigInt::from_hex(
                        "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8",
                    )
                    .unwrap(),
                    y: BigInt::from_hex(
                        "7561967ae7e35552012b5778030b36a39b62dfe899bb9edbbc57344e94f22db0",
                    )
                    .unwrap(),
                },
            ),
            // uncompressed with odd y
            (
                concat!(
                    "04",
                    "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8",
                    "8a9e6985181caaadfed4a887fcf4c95c649d20176644612443a8cbb06b0dce7f"
                ),
                Point {
                    x: BigInt::from_hex(
                        "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8",
                    )
                    .unwrap(),
                    y: BigInt::from_hex(
                        "8a9e6985181caaadfed4a887fcf4c95c649d20176644612443a8cbb06b0dce7f",
                    )
                    .unwrap(),
                },
            ),
            // compressed for even y
            (
                concat!(
                    "02",
                    "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8"
                ),
                Point {
                    x: BigInt::from_hex(
                        "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8",
                    )
                    .unwrap(),
                    y: BigInt::from_hex(
                        "7561967ae7e35552012b5778030b36a39b62dfe899bb9edbbc57344e94f22db0",
                    )
                    .unwrap(),
                },
            ),
            // compressed for odd y
            (
                concat!(
                    "03",
                    "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8"
                ),
                Point {
                    x: BigInt::from_hex(
                        "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8",
                    )
                    .unwrap(),
                    y: BigInt::from_hex(
                        "8a9e6985181caaadfed4a887fcf4c95c649d20176644612443a8cbb06b0dce7f",
                    )
                    .unwrap(),
                },
            ),
        ];

        for (hex, point) in data {
            let result = Sec1::decode_point(hex, secp256k1);
            assert_eq!(result.unwrap(), point);
        }
    }

    #[test]
    fn test_point_from_invalid_hex() {
        let secp256k1 = secp256k1();
        // (hex, err)
        let data = [
            // empty hex
            ("", PointDecodingError::InvalidFormat),
            // invalid prefix with hex too short
            ("09", PointDecodingError::InvalidFormat),
            // invalid prefix with uncompressed length
            (
                concat!(
                    "09",
                    "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8",
                    "7561967ae7e35552012b5778030b36a39b62dfe899bb9edbbc57344e94f22db0"
                ),
                PointDecodingError::InvalidFormat,
            ),
            // invalid prefix with compressed length
            (
                concat!(
                    "09",
                    "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8"
                ),
                PointDecodingError::InvalidFormat,
            ),
            // compressed x too short
            (concat!("03", "112233"), PointDecodingError::InvalidFormat),
            // uncompressed x too short
            (
                concat!(
                    "04",
                    "112233",
                    "8a9e6985181caaadfed4a887fcf4c95c649d20176644612443a8cbb06b0dce7f"
                ),
                PointDecodingError::InvalidFormat,
            ),
            // uncompressed y too short
            (
                concat!(
                    "04",
                    "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8",
                    "112233"
                ),
                PointDecodingError::InvalidFormat,
            ),
            // uncompressed x and y too short
            (
                concat!("04", "112233", "112233"),
                PointDecodingError::InvalidFormat,
            ),
            // x is not valid hex
            (
                concat!(
                    "04",
                    "DOGFOOD 48a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8",
                    "8a9e6985181caaadfed4a887fcf4c95c649d20176644612443a8cbb06b0dce7f"
                ),
                PointDecodingError::InvalidX,
            ),
            // y is not valid hex
            (
                concat!(
                    "04",
                    "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8",
                    "DOGFOOD 181caaadfed4a887fcf4c95c649d20176644612443a8cbb06b0dce7f"
                ),
                PointDecodingError::InvalidY,
            ),
            // y not found
            (
                concat!(
                    "02",
                    "0005153848a05cedf4630c2c512a245db2d8281eb1f566ac8768f98c66c042cf",
                ),
                PointDecodingError::YNotFound,
            ),
            // invalid curve point
            (
                concat!(
                    "04",
                    "42532038bd7d6162d3f54589cf6f96400dd5f0e17eec1a1841fe6c366e6d244b",
                    "29d81cd27a8a096b11d9b5a414b8f2e811da6aad4a694d4e7a9ae6b8f68e09ac"
                ),
                PointDecodingError::InvalidPoint,
            ),
        ];
        for (hex, err) in data {
            let result = Sec1::decode_point(hex, secp256k1);
            assert_eq!(
                *result
                    .err()
                    .unwrap()
                    .downcast_ref::<PointDecodingError>()
                    .unwrap(),
                err
            );
        }
    }
}
