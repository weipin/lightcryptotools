// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::BigInt;
use crate::crypto::ecdsa::ecdsa_encoding::SignatureEncoding;
use crate::crypto::ecdsa::Signature;
use crate::crypto::EllipticCurveParams;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// IEEE P1363 ECDSA signature encoding is the concatenation of the values r and s,
/// encoded as unsigned integers in big-endian order.

pub(crate) struct P1363;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureDecodingError {
    InvalidFormat,
    InvalidSignature,
}

impl Display for SignatureDecodingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureDecodingError::InvalidFormat => write!(f, "Invalid format"),
            SignatureDecodingError::InvalidSignature => write!(f, "Invalid signature"),
        }
    }
}

impl Error for SignatureDecodingError {}

impl SignatureEncoding for P1363 {
    fn decode<T: AsRef<[u8]>>(
        data: T,
        curve_params: &EllipticCurveParams,
    ) -> Result<Signature, Box<dyn Error>> {
        let data = data.as_ref();

        let element_hex_len = curve_params.base_point_order.byte_len() * 2;
        if data.len() != element_hex_len * 2 {
            return Err(Box::new(SignatureDecodingError::InvalidFormat));
        }

        let (r_hex, s_hex) = data.split_at(element_hex_len);

        let r = match BigInt::from_hex(r_hex) {
            Ok(r) => r,
            Err(_) => {
                return Err(Box::new(SignatureDecodingError::InvalidFormat));
            }
        };
        let s = match BigInt::from_hex(s_hex) {
            Ok(s) => s,
            Err(_) => {
                return Err(Box::new(SignatureDecodingError::InvalidFormat));
            }
        };

        match Signature::new(r, s, curve_params) {
            Some(signature) => Ok(signature),
            None => Err(Box::new(SignatureDecodingError::InvalidSignature)),
        }
    }

    /// Returns the hexadecimal representation of r and s concatenated with each other.
    ///
    /// For r or s with byte length less than the base point order length,
    /// the hexadecimal representation is leading zero padded.
    fn encode(signature: &Signature) -> String {
        let element_hex_len = signature.curve_params.base_point_order.byte_len() * 2;
        let r_hex = signature.r.to_lower_hex();
        let s_hex = signature.s.to_lower_hex();

        format!("{r_hex:0>element_hex_len$}{s_hex:0>element_hex_len$}")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::secp256k1;

    #[test]
    fn test_signature_encoding_decoding() {
        let secp256k1 = secp256k1();
        let data = [
            (
                &Signature::new(BigInt::one(), BigInt::from(2), secp256k1).unwrap(),
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                    "0000000000000000000000000000000000000000000000000000000000000002"
                ),
            ),
            (
                &Signature::new(
                    BigInt::from_hex(
                        "fbe907aac2bd7cd0ce3711f644235486367bdca4b87f19f76a7935fa00c6d169",
                    )
                    .unwrap(),
                    BigInt::from_hex(
                        "7f16095dd8cb6a4da57da25e3a3178665513e12c7b4dc52f2c212d250eef6407",
                    )
                    .unwrap(),
                    secp256k1,
                )
                .unwrap(),
                concat!(
                    "fbe907aac2bd7cd0ce3711f644235486367bdca4b87f19f76a7935fa00c6d169",
                    "7f16095dd8cb6a4da57da25e3a3178665513e12c7b4dc52f2c212d250eef6407"
                ),
            ),
        ];

        for (signature, signature_hex) in data {
            assert_eq!(P1363::encode(signature), signature_hex);

            let decoded = P1363::decode(signature_hex, secp256k1).unwrap();
            assert_eq!(decoded.r, signature.r);
            assert_eq!(decoded.s, signature.s);
        }
    }

    #[test]
    fn test_signature_decoding_error() {
        let secp256k1 = secp256k1();
        let data = [
            // incorrect length
            ("0011", SignatureDecodingError::InvalidFormat),
            // invalid hex char
            (
                concat!(
                    "XXXX07aac2bd7cd0ce3711f644235486367bdca4b87f19f76a7935fa00c6d169",
                    "7f16095dd8cb6a4da57da25e3a3178665513e12c7b4dc52f2c212d250eef6407"
                ),
                SignatureDecodingError::InvalidFormat,
            ),
            // invalid signature: r >= base point order
            (
                concat!(
                    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                    "7f16095dd8cb6a4da57da25e3a3178665513e12c7b4dc52f2c212d250eef6407"
                ),
                SignatureDecodingError::InvalidSignature,
            ),
            // invalid signature: s >= base point order
            (
                concat!(
                    "fbe907aac2bd7cd0ce3711f644235486367bdca4b87f19f76a7935fa00c6d169",
                    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
                ),
                SignatureDecodingError::InvalidSignature,
            ),
        ];

        for (hex, err) in data {
            assert_eq!(
                *P1363::decode(hex, secp256k1)
                    .unwrap_err()
                    .downcast_ref::<SignatureDecodingError>()
                    .unwrap(),
                err
            );
        }
    }
}
