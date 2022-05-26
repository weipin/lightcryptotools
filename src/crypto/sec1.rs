// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::BigInt;
use crate::crypto::codecs::bytes_to_lower_hex;
use crate::crypto::elliptic_curve_params::{EllipticCurveParams, EllipticCurveParamsEncoding};
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

impl EllipticCurveParamsEncoding for Sec1 {
    /// Decodes a Point as described in http://www.secg.org/SEC1-Ver-1.0.pdf,
    /// sections 2.3.3/2.3.4.
    ///
    /// uncompressed: '04' + x + y
    /// compressed:   '02'|'03' + x
    fn decode_point<T: AsRef<[u8]>>(
        data: T,
        curve_params: &EllipticCurveParams,
    ) -> Result<Point, Box<dyn std::error::Error>> {
        let hex_bytes = data.as_ref();
        let point_element_hex_len = curve_params.base_point_order.byte_len() * 2;

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
            if !curve_params.validate_point(&point) {
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
        let y_square = &x * &x * &x + &curve_params.curve.a * &x + &curve_params.curve.b;
        let y_square = modulo(&y_square, &curve_params.curve.p);

        let (root1, root2) = match sqrt(&y_square, &curve_params.curve.p) {
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
        if !curve_params.validate_point(&point) {
            return Err(Box::new(PointDecodingError::InvalidPoint));
        }

        Ok(point)
    }

    /// Encodes `point` as described in http://www.secg.org/SEC1-Ver-1.0.pdf,
    /// sections 2.3.3/2.3.4.
    ///
    /// uncompressed: '4' + x + y
    /// compressed:   '2'|'3' + x
    ///
    /// This method assumes that the caller has made sure `point` is legitimate,
    /// it does not validate `point` against `curve_params`.
    ///
    /// Both elements of `point` must be in the range (> 0 and < base_point_order),
    /// otherwise this function will panic.
    fn encode_point(
        point: &Point,
        curve_params: &EllipticCurveParams,
        compressed: bool,
    ) -> String {
        assert!(point.x > BigInt::zero() && point.x < curve_params.base_point_order);
        assert!(point.y > BigInt::zero() && point.y < curve_params.base_point_order);

        let hex_len = curve_params.base_point_order.byte_len() * 2;
        if compressed {
            if point.y.is_even() {
                let x_hex = point.x.to_hex();
                format!("02{x_hex:0>hex_len$}")
            } else {
                let x_hex = point.x.to_hex();
                format!("03{x_hex:0>hex_len$}")
            }
        } else {
            let hex = bytes_to_lower_hex(&curve_params.point_to_bytes(point));
            format!("04{hex}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ecdsa::{PrivateKey, PublicKey};
    use crate::crypto::secp256k1::secp256k1;
    use crate::testing_tools::quickcheck::HexString;
    use quickcheck::{Gen, QuickCheck};

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
            // invalid curve point (identity element)
            (
                concat!(
                    "04",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "0000000000000000000000000000000000000000000000000000000000000000"
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

    #[test]
    fn test_encode_point() {
        let secp256k1 = secp256k1();
        // (hex, point, compressed)
        let data = [
            // uncompressed
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
                false,
            ),
            // compressed with even y
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
                true,
            ),
            // compressed with odd y
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
                true,
            ),
            // uncompressed with small elements
            (
                concat!(
                    "04",
                    "00000000000000000000000000000000000000000000000000000000000042c8",
                    "00000000000000000000000000000000000000000000000000000000000dce7f"
                ),
                Point {
                    x: BigInt::from_hex("42c8").unwrap(),
                    y: BigInt::from_hex("0dce7f").unwrap(),
                },
                false,
            ),
            // compressed with small elements
            (
                concat!(
                    "03",
                    "000000000000000000000000000000000000000000000000000000000000e395"
                ),
                Point {
                    x: BigInt::from_hex("e395").unwrap(),
                    y: BigInt::from_hex(
                        "8a9e6985181caaadfed4a887fcf4c95c649d20176644612443a8cbb06b0dce7f",
                    )
                    .unwrap(),
                },
                true,
            ),
        ];
        for (hex, point, compressed) in data {
            assert_eq!(Sec1::encode_point(&point, secp256k1, compressed), hex);
        }
    }

    #[test]
    #[should_panic]
    fn test_encode_point_panic_with_negative_element() {
        let secp256k1 = secp256k1();
        let point = Point {
            x: BigInt::from(-1),
            y: BigInt::from(2),
        };
        Sec1::encode_point(&point, secp256k1, true);
    }

    #[test]
    #[should_panic]
    fn test_encode_point_panic_with_element_too_great() {
        let secp256k1 = secp256k1();
        let x_hex = concat!(
            "112233",
            "e395153848a05cedf4630c2c512a245db2d8281eb1f566cc8768f98c66c042c8"
        );
        let point = Point {
            x: BigInt::from_hex(x_hex).unwrap(),
            y: BigInt::from(2),
        };
        Sec1::encode_point(&point, secp256k1, true);
    }

    #[test]
    fn point_to_hex_double_conversion() {
        const GEN_SIZE: usize = 16;
        const TEST_NUMBER: u64 = 100;

        fn prop(d_hex: HexString) -> bool {
            let d = BigInt::from_hex(d_hex.0).unwrap();
            if d.is_zero() {
                return true; // ignore
            }

            let secp256k1 = secp256k1();
            let private_key =
                PrivateKey::new(d % &secp256k1.base_point_order, secp256k1).unwrap();
            let public_key = private_key.public_key();
            let hex = public_key.to_sec1_hex(true);
            let hex2 = PublicKey::from_sec1_hex(&hex, secp256k1)
                .unwrap()
                .to_sec1_hex(true);

            hex == hex2
        }

        QuickCheck::new()
            .gen(Gen::new(GEN_SIZE))
            .tests(TEST_NUMBER)
            .quickcheck(prop as fn(HexString) -> bool)
    }
}
