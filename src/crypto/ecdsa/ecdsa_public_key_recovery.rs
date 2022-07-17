// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::ecdsa_core::{
    hash_length_matches_base_point_order, SignatureRecoveryId,
    EMPTY_HASH_NOT_ALLOWED_ERROR_DISPLAY,
    HASH_BIT_LENGTH_DOES_NOT_MATCH_BASE_POINT_ORDER_ERROR_DISPLAY,
    ZERO_HASH_NOT_ALLOWED_ERROR_DISPLAY,
};
use crate::bigint::{BigInt, Sign};
use crate::crypto::ecdsa::{PublicKey, Signature};
use crate::math::{modular, Point};
use std::fmt;
use std::fmt::Display;

/// Recovers public keys that can verify the `signature` and `hash` pair.
/// The scope of the public keys can be narrowed by the optional `recovery_id`.
pub fn recover_public_keys_from_signature<'a>(
    signature: &Signature<'a>,
    hash: &[u8],
    recovery_id: Option<SignatureRecoveryId>,
) -> Result<Vec<PublicKey<'a>>, RecoveryError> {
    recover_public_keys_from_signature_with_options(
        signature,
        hash,
        recovery_id,
        &RecoveryOptions::default(),
    )
}

pub fn recover_public_keys_from_signature_with_options<'a>(
    signature: &Signature<'a>,
    hash: &[u8],
    recovery_id: Option<SignatureRecoveryId>,
    options: &RecoveryOptions,
) -> Result<Vec<PublicKey<'a>>, RecoveryError> {
    // SEC 1 Ver. 2.0[1], 4.1.6 Public Key Recovery Operation
    //
    // [1]: http://www.secg.org/SEC1-Ver-2.0.pdf

    if hash.is_empty() {
        return Err(RecoveryError::EmptyHashNotAllowed);
    }

    if options.strict_hash_byte_length
        && !hash_length_matches_base_point_order(hash.len(), signature.curve_params)
    {
        return Err(RecoveryError::HashBitLengthDoesNotMatchBasePointOrder);
    }

    let hash_n = BigInt::from_be_bytes_with_max_bits_len(
        hash,
        signature.curve_params.base_point_order.bit_len(),
        Sign::Positive,
    );
    if hash_n.is_zero() {
        return Err(RecoveryError::ZeroHashNotAllowed);
    }

    let (j_lower_bound, j_higher_bound) = if let Some(recovery_id) = recovery_id {
        match recovery_id {
            SignatureRecoveryId::LowXEvenY | SignatureRecoveryId::LowXOddY => (0, 0),
            SignatureRecoveryId::HighXEvenY | SignatureRecoveryId::HighXOddY => {
                (1, signature.curve_params.cofactor)
            }
        }
    } else {
        (0, signature.curve_params.cofactor)
    };

    let r_inverse =
        match modular::invert(&signature.r, &signature.curve_params.base_point_order) {
            None => {
                return Err(RecoveryError::InvalidSignature);
            }
            Some(r_inverse) => r_inverse,
        };
    let e_neg = modular::modulo(&(-&hash_n), &signature.curve_params.base_point_order);

    let mut public_keys = Vec::new();
    for j in j_lower_bound..=j_higher_bound {
        let x = &signature.r + BigInt::from(j) * &signature.curve_params.base_point_order;
        if x >= signature.curve_params.curve.p {
            break;
        }

        // y^2 = x^3 + a * x + b
        let y_squared = &x * &x * &x
            + &signature.curve_params.curve.a * &x
            + &signature.curve_params.curve.b;
        let y_squared = modular::modulo(&y_squared, &signature.curve_params.curve.p);

        let (y1, y2) = match modular::sqrt(&y_squared, &signature.curve_params.curve.p) {
            Some(roots) => roots,
            None => {
                continue;
            }
        };

        let mut points = Vec::with_capacity(2);
        if let Some(recovery_id) = recovery_id {
            match recovery_id {
                SignatureRecoveryId::LowXEvenY | SignatureRecoveryId::HighXEvenY => {
                    if y1.is_even() {
                        points.push(Point { x, y: y1 });
                    } else {
                        points.push(Point { x, y: y2 });
                    }
                }
                SignatureRecoveryId::LowXOddY | SignatureRecoveryId::HighXOddY => {
                    if y1.is_odd() {
                        points.push(Point { x, y: y1 });
                    } else {
                        points.push(Point { x, y: y2 });
                    }
                }
            }
        } else {
            points.push(Point {
                x: x.clone(),
                y: y1,
            });
            points.push(Point { x, y: y2 });
        };

        for point in points {
            // Q = r^−1 * (s * R − e * G)
            let s_mul_r = signature.curve_params.curve.mul_point(&point, &signature.s);
            let e_neg_mul_g = signature
                .curve_params
                .curve
                .mul_point(&signature.curve_params.base_point, &e_neg);

            let q = signature
                .curve_params
                .curve
                .add_points(&s_mul_r, &e_neg_mul_g);
            let q = signature.curve_params.curve.mul_point(&q, &r_inverse);

            if let Some(public_key) = PublicKey::new(q, signature.curve_params) {
                if public_key.verify(&hash_n, signature) {
                    public_keys.push(public_key);
                }
            }
        }
    } // j loop

    Ok(public_keys)
}

pub struct RecoveryOptions {
    pub strict_hash_byte_length: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            strict_hash_byte_length: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryError {
    EmptyHashNotAllowed,
    ZeroHashNotAllowed,
    HashBitLengthDoesNotMatchBasePointOrder,
    InvalidSignature,
}

impl Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryError::EmptyHashNotAllowed => {
                write!(f, "{}", EMPTY_HASH_NOT_ALLOWED_ERROR_DISPLAY)
            }
            RecoveryError::ZeroHashNotAllowed => {
                write!(f, "{}", ZERO_HASH_NOT_ALLOWED_ERROR_DISPLAY)
            }
            RecoveryError::HashBitLengthDoesNotMatchBasePointOrder => {
                write!(
                    f,
                    "{}",
                    HASH_BIT_LENGTH_DOES_NOT_MATCH_BASE_POINT_ORDER_ERROR_DISPLAY
                )
            }
            RecoveryError::InvalidSignature => {
                write!(f, "Invalid Signature")
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::hex_to_bytes;
    use crate::crypto::ecdsa::{sign_with_options, PrivateKey, SigningOptions};
    use crate::crypto::secp256k1;

    #[test]
    fn test_recover_public_keys() {
        let secp256k1 = secp256k1();

        let hash_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        let hash = hex_to_bytes(hash_hex).unwrap();
        let d = BigInt::from(1);

        let private_key = PrivateKey::new(d, secp256k1).unwrap();
        let (signature, recovery_id) = sign_with_options(
            &hash,
            &private_key,
            &SigningOptions {
                enforce_low_s: false,
                employ_extra_random_data: false,
                ..Default::default()
            },
        )
        .unwrap();

        // with recovery_id
        let public_keys =
            recover_public_keys_from_signature(&signature, &hash, Some(recovery_id)).unwrap();
        assert_eq!(public_keys.len(), 1);
        assert_eq!(public_keys[0], private_key.public_key());

        // without recovery_id
        let public_keys = recover_public_keys_from_signature(&signature, &hash, None).unwrap();
        assert_eq!(public_keys.len(), 2);
    }

    #[test]
    fn test_recover_public_keys_ignores_invalid_keys() {
        let secp256k1 = secp256k1();

        let hash =
            hex_to_bytes("6b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9")
                .unwrap();
        let r = BigInt::from_hex(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let s = BigInt::from_hex(
            "6b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9",
        )
        .unwrap();
        let signature = Signature::new(r, s, secp256k1).unwrap();

        let public_keys = recover_public_keys_from_signature(&signature, &hash, None).unwrap();
        // One of the public keys is invalid
        assert_eq!(public_keys.len(), 1);
    }

    #[test]
    fn test_recover_public_keys_err_cases() {
        let secp256k1 = secp256k1();
        let signature = Signature::new(BigInt::one(), BigInt::one(), secp256k1).unwrap();

        assert_eq!(
            recover_public_keys_from_signature_with_options(
                &signature,
                &[],
                None,
                &RecoveryOptions {
                    strict_hash_byte_length: false
                }
            )
            .unwrap_err(),
            RecoveryError::EmptyHashNotAllowed
        );
        assert_eq!(
            recover_public_keys_from_signature_with_options(
                &signature,
                &[0],
                None,
                &RecoveryOptions {
                    strict_hash_byte_length: false
                }
            )
            .unwrap_err(),
            RecoveryError::ZeroHashNotAllowed
        );
    }
}
