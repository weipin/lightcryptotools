// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

///! Implements RFC 6979
use crate::bigint::bigint_core::{BigInt, Sign};
use crate::crypto::ecdsa::PrivateKey;
use crate::crypto::hash::{hmac, UnkeyedHash};
use crate::random;
use crate::random::GetOsRandomBytesError;
use std::fmt;
use std::fmt::Display;

pub(crate) struct Rfc6979 {
    // Base point order of the elliptic curve domain parameters.
    q: BigInt,

    // Binary length of `q`.
    qlen: usize,

    // The number rounded up to the next multiple of `qlen`.
    rlen: usize,

    // Section 3.6 of RFC6979
    employ_extra_random_data: bool,
}

impl Rfc6979 {
    pub(crate) fn new(q: BigInt, employ_extra_random_data: bool) -> Rfc6979 {
        let qlen = q.bit_len();
        let rlen = ((qlen + 7) / 8) * 8;

        Rfc6979 {
            q,
            qlen,
            rlen,
            employ_extra_random_data,
        }
    }

    pub(crate) fn generate_nonce<H: UnkeyedHash>(
        &self,
        hash: &[u8],
        private_key: &PrivateKey,
        hasher: &mut H,
    ) -> Result<BigInt, GenerateNonceError> {
        debug_assert_eq!(self.q, private_key.curve_params.base_point_order);

        let mut key_and_msg = self.int2octets(&private_key.data);
        key_and_msg.extend(&self.bits2octets(hash));
        if self.employ_extra_random_data {
            match random::generator::get_os_random_bytes(32) {
                Ok(bytes) => {
                    key_and_msg.extend(&bytes);
                }
                Err(err) => {
                    return Err(GenerateNonceError::FailedToGenerateRandomBytes(err));
                }
            }
        }

        let mut v = vec![1_u8; H::OUTPUT_BYTE_LENGTH];
        let mut k = vec![0_u8; H::OUTPUT_BYTE_LENGTH];

        // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
        let mut t = v.clone();
        t.push(0);
        t.extend(&key_and_msg);
        k = hmac(&k, &t, hasher);

        // V = HMAC_K(V)
        v = hmac(&k, &v, hasher);

        // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
        t.clear();
        t.extend(&v);
        t.push(1);
        t.extend(&key_and_msg);
        k = hmac(&k, &t, hasher);

        // V = HMAC_K(V)
        v = hmac(&k, &v, hasher);

        loop {
            // Set T to the empty sequence
            t.clear();

            // While tlen < qlen
            while t.len() * 8 < self.qlen {
                // V = HMAC_K(V)
                v = hmac(&k, &v, hasher);
                t.extend(&v);
            }

            let nonce = self.bits2int(&t);
            if nonce > BigInt::zero() && nonce < self.q {
                return Ok(nonce);
            }

            // K = HMAC_K(V || 0x00)
            t.clear();
            t.extend(&v);
            t.push(0);
            k = hmac(&k, &t, hasher);
            // V = HMAC_K(V)
            v = hmac(&k, &v, hasher);
        }
    }

    /// Returns a non-negative integer that is less than `2^qlen`.
    fn bits2int(&self, bytes: &[u8]) -> BigInt {
        // http://tools.ietf.org/html/rfc6979#section-2.3.2
        let mut n = BigInt::from_be_bytes(bytes, Sign::Positive);
        let blen = bytes.len() * 8;

        if blen > self.qlen {
            n = n >> (blen - self.qlen);
        }
        n
    }

    fn int2octets(&self, n: &BigInt) -> Vec<u8> {
        // http://tools.ietf.org/html/rfc6979#section-2.3.3
        assert!(n < &self.q);
        let mut bytes = n.to_be_bytes();
        if self.rlen / 8 > bytes.len() {
            let padding_len = self.rlen / 8 - bytes.len();
            bytes.extend(&vec![0; padding_len]);
            bytes.rotate_right(padding_len);
        }

        bytes
    }

    fn bits2octets(&self, bytes: &[u8]) -> Vec<u8> {
        // http://tools.ietf.org/html/rfc6979#section-2.3.4
        let z1 = self.bits2int(bytes);
        let z2 = z1 % &self.q;
        self.int2octets(&z2)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum GenerateNonceError {
    FailedToGenerateRandomBytes(GetOsRandomBytesError),
}

impl Display for GenerateNonceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenerateNonceError::FailedToGenerateRandomBytes(err) => {
                write!(f, "Failed to generate random bytes: {err}")
            }
        }
    }
}

impl std::error::Error for GenerateNonceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ecdsa::PrivateKey;
    use crate::crypto::elliptic_curve_params::EllipticCurveParams;
    use crate::crypto::hash::Sha256;

    #[test]
    fn test_generate_nonce() {
        let q = BigInt::from_hex("04000000000000000000020108a2e0cc0d99f8a5ef").unwrap();
        let curve_params = EllipticCurveParams {
            base_point_order: q.clone(),
            ..Default::default()
        };

        let private_key = PrivateKey::new(
            BigInt::from_hex("009a4d6792295a7f730fc3f2b49cbc0f62e862272f").unwrap(),
            &curve_params,
        )
        .unwrap();
        let rfc6979 = Rfc6979::new(q, false);

        let mut hasher = Sha256::new();
        let hash = hasher.digest("sample");
        let k = rfc6979.generate_nonce(&hash, &private_key, &mut hasher);
        assert_eq!(
            k.unwrap().to_lower_hex(),
            "023af4074c90a02b3fe61d286d5c87f425e6bdd81b"
        );
    }
}
