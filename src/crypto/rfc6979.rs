// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::{BigInt, Sign};
use crate::crypto::ecdsa::PrivateKey;
use ring::hmac;
use ring::hmac::Algorithm;

pub(crate) struct Rfc6979 {
    // Base point order of the elliptic curve domain.
    q: BigInt,

    // Binary length of `q`.
    qlen: usize,

    // The number rounded up to the next multiple of `qlen`.
    rlen: usize,
}

impl Rfc6979 {
    pub(crate) fn new(q: BigInt) -> Rfc6979 {
        let qlen = q.bit_len();
        let rlen = ((qlen + 7) / 8) * 8;

        Rfc6979 { q, qlen, rlen }
    }

    pub(crate) fn generate_nonce(
        &self,
        hash: &[u8],
        private_key: &PrivateKey,
        algorithm: &'static Algorithm,
    ) -> BigInt {
        assert_eq!(self.q, private_key.curve_domain.base_point_order);

        let hash_size = algorithm.digest_algorithm().output_len;

        let mut key_and_msg = self.int2octets(&private_key.data);
        key_and_msg.extend_from_slice(&self.bits2octets(hash));
        let v = vec![1_u8; hash_size];
        let k = vec![0_u8; hash_size];

        let key = hmac::Key::new(*algorithm, &k);
        let mut t = v.clone();
        t.push(0);
        t.extend_from_slice(&key_and_msg);
        let k_tag = hmac::sign(&key, &t);
        let key = hmac::Key::new(*algorithm, k_tag.as_ref());
        let v_tag = hmac::sign(&key, &v);

        let key = hmac::Key::new(*algorithm, k_tag.as_ref());
        let mut t = v_tag.as_ref().to_vec();
        t.push(1);
        t.extend_from_slice(&key_and_msg);
        let mut k_tag = hmac::sign(&key, &t);
        let key = hmac::Key::new(*algorithm, k_tag.as_ref());
        let mut v_tag = hmac::sign(&key, v_tag.as_ref());

        let mut key = hmac::Key::new(*algorithm, k_tag.as_ref());
        loop {
            let mut t: Vec<u8> = vec![];
            while t.len() * 8 < self.qlen {
                v_tag = hmac::sign(&key, v_tag.as_ref());
                t.extend(v_tag.as_ref());
            }

            let nonce = self.bits2int(&t);
            if nonce > BigInt::zero() && nonce < self.q {
                return nonce;
            }

            let mut t = v_tag.as_ref().to_vec();
            t.push(0);
            k_tag = hmac::sign(&key, &t);
            key = hmac::Key::new(*algorithm, k_tag.as_ref());
            v_tag = hmac::sign(&key, v_tag.as_ref());
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
        // http://tools.ietf.org/html/rfc6979#section-2.3.4
        assert!(n < &self.q);
        let mut bytes = n.to_be_bytes();
        if self.rlen / 8 > bytes.len() {
            let padding_len = self.rlen / 8 - bytes.len();
            bytes.extend(vec![0; padding_len]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ecdsa::PrivateKey;
    use crate::crypto::elliptic_curve_domain::EllipticCurveDomain;
    use ring::digest;

    #[test]
    fn test_generate_nonce() {
        let q = BigInt::from_hex("4000000000000000000020108a2e0cc0d99f8a5ef").unwrap();
        let curve_domain = EllipticCurveDomain {
            base_point_order: q.clone(),
            ..Default::default()
        };

        let private_key = PrivateKey {
            data: BigInt::from_hex("09a4d6792295a7f730fc3f2b49cbc0f62e862272f").unwrap(),
            curve_domain: &curve_domain,
        };
        let rfc6979 = Rfc6979::new(q);

        let message = b"sample";
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(message);
        let digest = context.finish();
        let hash = digest.as_ref();

        let k = rfc6979.generate_nonce(hash, &private_key, &hmac::HMAC_SHA256);
        assert_eq!(k.to_hex(), "23af4074c90a02b3fe61d286d5c87f425e6bdd81b");
    }
}
