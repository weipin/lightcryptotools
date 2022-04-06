// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::Sign;
use crate::bigint::BigInt;
use crate::crypto::ecdsa::ecdsa_core::Signature;
use crate::crypto::ecdsa::ecdsa_key::PublicKey;

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum VerifyingError {
    StrictHighSFound,
}

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
    if options.enforce_low_s && !signature.is_low_s_signature() {
        return Err(VerifyingError::StrictHighSFound);
    }

    let hash_n = BigInt::from_be_bytes_with_max_bits_len(
        hash,
        public_key.curve_params.base_point_order.bit_len(),
        Sign::Positive,
    );

    let result = public_key.verify(&hash_n, signature);
    Ok(result)
}

pub struct VerifyingOptions {
    pub enforce_low_s: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for VerifyingOptions {
    fn default() -> Self {
        Self {
            enforce_low_s: false,
        }
    }
}
