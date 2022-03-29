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

pub fn sign<'a>(hash: &[u8], private_key: &'a PrivateKey<'a>) -> Signature<'a> {
    sign_with_options(hash, private_key, &SigningOptions::default())
}

pub fn sign_with_options<'a>(
    hash: &[u8],
    private_key: &'a PrivateKey<'a>,
    options: &SigningOptions,
) -> Signature<'a> {
    let hash_n = BigInt::from_be_bytes_with_max_bits_len(
        hash,
        private_key.curve_domain.base_point_order.bit_len(),
        Sign::Positive,
    );

    let rfc6979 = Rfc6979::new(private_key.curve_domain.base_point_order.clone());
    loop {
        let k = rfc6979.generate_nonce(hash, private_key, options.hmac_hash_algorithm);
        if let Some(signature) = private_key.sign(&hash_n, &k) {
            return if options.enforce_low_s {
                signature.to_low_s_signature()
            } else {
                signature
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

impl<'a> Signature<'a> {
    /// Returns a signature and ensures its `s` is at most the curve order divided by 2,
    /// (essentially restricting this value to its lower half range).
    ///
    /// For "low s" details see [BIP: 146][1]
    /// [1]: https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
    fn to_low_s_signature(&self) -> Signature<'a> {
        if self.s > (&self.curve_domain.base_point_order >> 1) {
            return Signature {
                r: self.r.clone(),
                s: (&self.curve_domain.base_point_order - &self.s),
                curve_domain: self.curve_domain,
            };
        }

        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1;

    #[test]
    fn test_to_low_s_signature() {
        // For secp256k1
        // low s in [0x1, 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0]
        let secp256k1 = secp256k1();
        let curve_order_half = BigInt::from_hex(
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
        )
        .unwrap();
        // s1, s2
        let data = [
            (BigInt::one(), BigInt::one()),
            (curve_order_half.clone(), curve_order_half.clone()),
            (
                &curve_order_half + BigInt::one(),
                BigInt::from_hex(
                    "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                )
                .unwrap(),
            ),
        ];

        for (s1, s2) in data {
            let signature = Signature {
                r: BigInt::zero(),
                s: s1,
                curve_domain: secp256k1,
            };
            assert_eq!(signature.to_low_s_signature().s, s2);
        }
    }
}
