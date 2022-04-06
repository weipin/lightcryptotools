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
pub enum SigningError {}

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

    // SEC1: truncates the hash to the bit-length of the curve base point order.
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
}

impl Default for SigningOptions {
    fn default() -> Self {
        Self {
            hmac_hash_algorithm: &hmac::HMAC_SHA256,
            enforce_low_s: true,
        }
    }
}
