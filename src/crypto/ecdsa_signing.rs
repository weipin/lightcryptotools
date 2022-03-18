// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::ecdsa_core::EcdsaSignature;
use super::ecdsa_core::PrivateKey;
use super::elliptic_curve_domain::EllipticCurveDomain;
use super::rfc6979::Rfc6979;
use crate::bigint::bigint_core::Sign;
use crate::bigint::BigInt;
use ring::{digest, hmac};

pub struct Algorithm {
    digest_algorithm: &'static digest::Algorithm,
    hmac_algorithm: &'static hmac::Algorithm,
}

pub fn sign(
    message: &[u8],
    private_key: &PrivateKey,
    curve_domain: EllipticCurveDomain,
    algorithm: &Algorithm,
) -> EcdsaSignature {
    let mut context = digest::Context::new(algorithm.digest_algorithm);
    context.update(message);
    let digest = context.finish();
    let hash = digest.as_ref();
    let hash_n = BigInt::from_be_bytes_with_max_bits_len(
        hash,
        curve_domain.base_point_order.bit_len(),
        Sign::Positive,
    );

    let rfc6979 = Rfc6979::new(curve_domain.base_point_order.clone());
    loop {
        let k = rfc6979.generate_nonce(hash, private_key, algorithm.hmac_algorithm);
        if let Some(signature) = curve_domain.sign(&hash_n, private_key, &k) {
            return signature;
        }
    }
}
