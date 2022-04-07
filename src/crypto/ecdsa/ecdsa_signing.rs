// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::Sign;
use crate::bigint::BigInt;
use crate::crypto::ecdsa::ecdsa_core::Signature;
use crate::crypto::ecdsa::ecdsa_key::PrivateKey;
use crate::crypto::rfc6979::Rfc6979;
use ring::hmac;

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum SigningError {
    EmptyHash,
    HashBitLengthDoesNotEqualBasePointOrder,
}

pub fn sign<'a>(
    hash: &[u8],
    private_key: &'a PrivateKey,
) -> Result<Signature<'a>, SigningError> {
    sign_with_options(hash, private_key, &SigningOptions::default())
}

pub fn sign_with_options<'a>(
    hash: &[u8],
    private_key: &'a PrivateKey,
    options: &SigningOptions,
) -> Result<Signature<'a>, SigningError> {
    assert!(private_key.is_valid());

    if hash.is_empty() {
        return Err(SigningError::EmptyHash);
    }

    if options.strict_hash_byte_length {
        assert_eq!(
            private_key.curve_params.base_point_order.bit_len() % 8,
            0,
            "The bit length of the order of the base point is not 1-byte aligned.\
            Call `sign_with_options` and specify the `SigningOptions` with `strict_hash_byte_length` set to `false`"
        );

        if hash.len() * 8 != private_key.curve_params.base_point_order.bit_len() {
            return Err(SigningError::HashBitLengthDoesNotEqualBasePointOrder);
        }
    }

    // SEC1: truncates the hash to the bit length of the order of the base point.
    let hash_n = BigInt::from_be_bytes_with_max_bits_len(
        hash,
        private_key.curve_params.base_point_order.bit_len(),
        Sign::Positive,
    );

    let rfc6979 = Rfc6979::new(private_key.curve_params.base_point_order.clone());
    loop {
        // TODO: Fix the Minerva vulnerability
        // https://minerva.crocs.fi.muni.cz/
        let k = rfc6979.generate_nonce(hash, private_key, options.hmac_hash_algorithm);
        if let Some(signature) = private_key.sign(&hash_n, &k) {
            return if options.enforce_low_s {
                Ok(signature.to_low_s_signature())
            } else {
                Ok(signature)
            };
        }
    }
}

pub struct SigningOptions {
    pub hmac_hash_algorithm: &'static hmac::Algorithm,
    pub enforce_low_s: bool,
    pub strict_hash_byte_length: bool,
}

impl Default for SigningOptions {
    fn default() -> Self {
        Self {
            hmac_hash_algorithm: &hmac::HMAC_SHA256,
            enforce_low_s: true,
            strict_hash_byte_length: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::BigInt;
    use crate::crypto::ecdsa::PrivateKey;
    use crate::crypto::EllipticCurveParams;

    #[test]
    fn test_sign_err_cases() {
        let curve = EllipticCurveParams {
            base_point_order: BigInt::from_hex(
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            )
            .unwrap(),
            ..Default::default()
        };
        let private_key = PrivateKey::new(BigInt::one(), &curve).unwrap();

        // EmptyHash
        assert_eq!(
            sign(&[], &private_key).unwrap_err(),
            SigningError::EmptyHash
        );

        // HashBitLengthDoesNotEqualBasePointOrder
        assert_eq!(
            sign(&[1], &private_key).unwrap_err(),
            SigningError::HashBitLengthDoesNotEqualBasePointOrder
        );
    }

    #[test]
    #[should_panic]
    fn test_sign_with_curve_base_point_order_not_byte_aligned() {
        let curve = EllipticCurveParams {
            base_point_order: BigInt::from(12),
            ..Default::default()
        };
        let private_key = PrivateKey::new(BigInt::one(), &curve).unwrap();
        let _ = sign(&[1], &private_key);
    }
}
