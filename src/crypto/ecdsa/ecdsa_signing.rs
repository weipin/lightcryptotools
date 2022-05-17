// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::Sign;
use crate::bigint::BigInt;
use crate::crypto::ecdsa::ecdsa_core::Signature;
use crate::crypto::ecdsa::ecdsa_key::PrivateKey;
use crate::crypto::hash::{Sha256, UnkeyedHash};
use crate::crypto::rfc6979::{GenerateNonceError, Rfc6979};
use std::fmt;
use std::fmt::Display;

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum SigningError {
    EmptyHash,
    HashBitLengthDoesNotMatchBasePointOrder,
    FailedToGenerateNonce(GenerateNonceError),
}

impl Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningError::EmptyHash => {
                write!(f, "Empty hash is not allowed")
            }
            SigningError::HashBitLengthDoesNotMatchBasePointOrder => {
                write!(f, "Hash bit length doesn't equal to the bit length of the order of the base point")
            }
            SigningError::FailedToGenerateNonce(err) => {
                write!(f, "Failed to generate deterministic nonce: {err}")
            }
        }
    }
}

impl std::error::Error for SigningError {}

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
    sign_with_options_and_rfc6979_hmac_hasher(hash, private_key, options, &mut Sha256::new())
}

pub fn sign_with_options_and_rfc6979_hmac_hasher<'a, H: UnkeyedHash>(
    hash: &[u8],
    private_key: &'a PrivateKey,
    options: &SigningOptions,
    hmac_hasher: &mut H,
) -> Result<Signature<'a>, SigningError> {
    if hash.is_empty() {
        return Err(SigningError::EmptyHash);
    }

    if options.strict_hash_byte_length {
        debug_assert_eq!(
            private_key.curve_params.base_point_order.bit_len() % 8,
            0,
            "The bit length of the order of the base point is not 1-byte aligned."
        );

        if hash.len() * 8 != private_key.curve_params.base_point_order.bit_len() {
            return Err(SigningError::HashBitLengthDoesNotMatchBasePointOrder);
        }
    }

    // SEC1: truncates the hash to the bit length of the order of the base point.
    let hash_n = BigInt::from_be_bytes_with_max_bits_len(
        hash,
        private_key.curve_params.base_point_order.bit_len(),
        Sign::Positive,
    );

    let rfc6979 = Rfc6979::new(
        private_key.curve_params.base_point_order.clone(),
        options.employ_extra_random_data,
    );
    loop {
        // TODO: Fix the Minerva vulnerability
        // https://minerva.crocs.fi.muni.cz/
        let k = match rfc6979.generate_nonce(hash, private_key, hmac_hasher) {
            Ok(nonce) => nonce,
            Err(err) => {
                return Err(SigningError::FailedToGenerateNonce(err));
            }
        };
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
    pub enforce_low_s: bool,
    pub strict_hash_byte_length: bool,
    pub employ_extra_random_data: bool,
}

impl Default for SigningOptions {
    fn default() -> Self {
        Self {
            enforce_low_s: true,
            strict_hash_byte_length: true,
            employ_extra_random_data: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::BigInt;
    use crate::crypto::codecs::hex_to_bytes;
    use crate::crypto::ecdsa::PrivateKey;
    use crate::crypto::{secp256k1, EllipticCurveParams};
    use crate::random::{generator, GetOsRandomBytesError};
    use devtools::path::integration_testing_data_path;
    use serde_json::Value;
    use std::fs::File;
    use std::iter::zip;

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

        assert_eq!(
            sign_with_options(
                &[],
                &private_key,
                &SigningOptions {
                    employ_extra_random_data: false,
                    ..Default::default()
                }
            )
            .unwrap_err(),
            SigningError::EmptyHash
        );

        assert_eq!(
            sign_with_options(
                &[1],
                &private_key,
                &SigningOptions {
                    employ_extra_random_data: false,
                    ..Default::default()
                }
            )
            .unwrap_err(),
            SigningError::HashBitLengthDoesNotMatchBasePointOrder
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
        let _ = sign_with_options(
            &[1],
            &private_key,
            &SigningOptions {
                employ_extra_random_data: false,
                ..Default::default()
            },
        );
    }

    #[test]
    fn test_sign_with_extra_random_data() {
        let secp256k1 = secp256k1();

        let extra_data_hex_vec = [
            "0000000000000000000000000000000000000000000000000000000000000000", // extraEntropy0
            "0000000000000000000000000000000000000000000000000000000000000001", // extraEntropy1
            "6e723d3fd94ed5d2b6bdd4f123364b0f3ca52af829988a63f8afe91d29db1c33", // extraEntropyRand
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", // extraEntropyN
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // extraEntropyMax
        ];
        let extra_data_vec = extra_data_hex_vec.map(|hex| hex_to_bytes(hex).unwrap());

        let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/ecdsa.json");
        let file = File::open(path).unwrap();
        let root: Value = serde_json::from_reader(file).unwrap();
        let value_vec = root["extraEntropy"].as_array().unwrap();
        for value in value_vec {
            let d_hex = value["d"].as_str().unwrap();
            let m_hex = value["m"].as_str().unwrap();
            let signature_hex = value["signature"].as_str().unwrap();
            let signature_hex_with_extra_data_vec = [
                value["extraEntropy0"].as_str().unwrap(),
                value["extraEntropy1"].as_str().unwrap(),
                value["extraEntropyRand"].as_str().unwrap(),
                value["extraEntropyN"].as_str().unwrap(),
                value["extraEntropyMax"].as_str().unwrap(),
            ];

            let private_key =
                PrivateKey::new(BigInt::from_hex(d_hex).unwrap(), secp256k1).unwrap();

            // without extra data
            let signature = sign_with_options(
                &hex_to_bytes(m_hex).unwrap(),
                &private_key,
                &SigningOptions {
                    employ_extra_random_data: false,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(signature.to_p1363_hex(), signature_hex);

            // with extra data
            for (extra_data, &signature_hex) in zip(
                extra_data_vec.clone().into_iter(),
                signature_hex_with_extra_data_vec.iter(),
            ) {
                {
                    let ctx = generator::get_os_random_bytes_context();
                    ctx.expect().return_once(|_| Ok(extra_data));

                    let signature = sign_with_options(
                        &hex_to_bytes(m_hex).unwrap(),
                        &private_key,
                        &SigningOptions {
                            employ_extra_random_data: true,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                    assert_eq!(signature.to_p1363_hex(), signature_hex);
                }
            }
        }

        // err
        let ctx = generator::get_os_random_bytes_context();
        ctx.expect()
            .return_once(|_| Err(GetOsRandomBytesError::LinuxGetRandom(17)));

        let private_key = PrivateKey::new(BigInt::one(), secp256k1).unwrap();
        let err = sign_with_options(
            &[77],
            &private_key,
            &SigningOptions {
                employ_extra_random_data: true,
                strict_hash_byte_length: false,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            format!("{err}"),
            concat!(
                "Failed to generate deterministic nonce: ",
                "Failed to generate random bytes: getrandom failed with errno 17"
            )
        );
    }
}
