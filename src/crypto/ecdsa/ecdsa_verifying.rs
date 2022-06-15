// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::ecdsa_core::{
    hash_length_matches_base_point_order, Signature, EMPTY_HASH_NOT_ALLOWED_ERROR_DISPLAY,
    HASH_BIT_LENGTH_DOES_NOT_MATCH_BASE_POINT_ORDER_ERROR_DISPLAY,
    ZERO_HASH_NOT_ALLOWED_ERROR_DISPLAY,
};
use super::ecdsa_key::PublicKey;
use crate::bigint::bigint_core::Sign;
use crate::bigint::BigInt;
use std::fmt;
use std::fmt::Display;

pub fn verify(
    hash: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<bool, VerifyingError> {
    verify_with_options(hash, signature, public_key, &VerifyingOptions::default())
}

pub fn verify_with_options(
    hash: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
    options: &VerifyingOptions,
) -> Result<bool, VerifyingError> {
    if hash.is_empty() {
        return Err(VerifyingError::EmptyHashNotAllowed);
    }

    if options.enforce_low_s && !signature.is_low_s_signature() {
        return Err(VerifyingError::StrictHighSFound);
    }

    if options.strict_hash_byte_length
        && !hash_length_matches_base_point_order(hash.len(), public_key.curve_params)
    {
        return Err(VerifyingError::HashBitLengthDoesNotMatchBasePointOrder);
    }

    let hash_n = BigInt::from_be_bytes_with_max_bits_len(
        hash,
        public_key.curve_params.base_point_order.bit_len(),
        Sign::Positive,
    );
    if hash_n.is_zero() {
        return Err(VerifyingError::ZeroHashNotAllowed);
    }

    let result = public_key.verify(&hash_n, signature);
    Ok(result)
}

pub struct VerifyingOptions {
    pub enforce_low_s: bool,
    pub strict_hash_byte_length: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for VerifyingOptions {
    fn default() -> Self {
        Self {
            enforce_low_s: false,
            strict_hash_byte_length: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum VerifyingError {
    EmptyHashNotAllowed,
    ZeroHashNotAllowed,
    StrictHighSFound,
    HashBitLengthDoesNotMatchBasePointOrder,
}

impl Display for VerifyingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyingError::EmptyHashNotAllowed => {
                write!(f, "{}", EMPTY_HASH_NOT_ALLOWED_ERROR_DISPLAY)
            }
            VerifyingError::ZeroHashNotAllowed => {
                write!(f, "{}", ZERO_HASH_NOT_ALLOWED_ERROR_DISPLAY)
            }
            VerifyingError::StrictHighSFound => {
                write!(f, "A \"high s\" is found when \"low s\" is enforced")
            }
            VerifyingError::HashBitLengthDoesNotMatchBasePointOrder => {
                write!(
                    f,
                    "{}",
                    HASH_BIT_LENGTH_DOES_NOT_MATCH_BASE_POINT_ORDER_ERROR_DISPLAY
                )
            }
        }
    }
}

impl std::error::Error for VerifyingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ecdsa::{sign_with_options, PrivateKey, SigningOptions};
    use crate::crypto::secp256k1;

    #[test]
    fn test_verifying_err_cases() {
        let secp256k1 = secp256k1();

        let d = BigInt::from(1);
        let private_key = PrivateKey::new(d, secp256k1).unwrap();
        let public_key = private_key.public_key();
        let (signature, _) = sign_with_options(
            &[1],
            &private_key,
            &SigningOptions {
                strict_hash_byte_length: false,
                employ_extra_random_data: false,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(
            verify_with_options(
                &[],
                &signature,
                &public_key,
                &VerifyingOptions {
                    strict_hash_byte_length: false,
                    ..Default::default()
                }
            )
            .unwrap_err(),
            VerifyingError::EmptyHashNotAllowed
        );

        assert_eq!(
            verify_with_options(
                &[0],
                &signature,
                &public_key,
                &VerifyingOptions {
                    strict_hash_byte_length: false,
                    ..Default::default()
                }
            )
            .unwrap_err(),
            VerifyingError::ZeroHashNotAllowed
        );
    }
}
