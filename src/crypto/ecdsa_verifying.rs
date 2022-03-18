// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::Sign;
use crate::bigint::BigInt;
use crate::crypto::ecdsa_core::{EcdsaSignature, PublicKey};
use crate::crypto::elliptic_curve_domain::EllipticCurveDomain;
use ring::digest;
use ring::digest::Algorithm;

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum EcdsaVerifyingError {
    InvalidPublicKey,
}

pub fn verify(
    message: &[u8],
    signature: &EcdsaSignature,
    public_key: &PublicKey,
    curve_domain: EllipticCurveDomain,
    algorithm: &'static Algorithm,
) -> Result<bool, EcdsaVerifyingError> {
    if !curve_domain.validate_point(public_key) {
        return Err(EcdsaVerifyingError::InvalidPublicKey);
    }

    let mut context = digest::Context::new(algorithm);
    context.update(message);
    let digest = context.finish();
    let hash = digest.as_ref();
    let hash_n = BigInt::from_be_bytes_with_max_bits_len(
        hash,
        curve_domain.base_point_order.bit_len(),
        Sign::Positive,
    );

    let result = curve_domain.verify(signature, &hash_n, public_key);
    Ok(result)
}
