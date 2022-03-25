// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::ecdsa_key::{PrivateKey, PublicKey};
use super::elliptic_curve_domain::EllipticCurveDomain;
use crate::bigint::bigint_core::{BigInt, Sign};
use crate::math::modular::{invert, modulo};

pub struct EcdsaSignature {
    r: BigInt,
    s: BigInt,
}

impl EllipticCurveDomain {
    /// Generates a ECDSA signature of `hash_n` with `private_key`.
    /// `k` is a random number between 1 and n – 1.
    ///
    /// Returns None if either element of the signature (`r` or `s`) is zero.
    pub(crate) fn sign(
        &self,
        hash_n: &BigInt,
        private_key: &PrivateKey,
        k: &BigInt,
    ) -> Option<EcdsaSignature> {
        assert_eq!(private_key.curve_domain, self);
        assert!(hash_n.bit_len() <= self.base_point_order.bit_len());

        // `k` in [1, n - 1]
        // n: base point order
        assert!(k > &BigInt::zero() && k < &self.base_point_order);

        let kg = self.curve.mul_point(&self.base_point, k);
        let r = kg.x;
        let r = modulo(&r, &self.base_point_order);
        if r.is_zero() {
            return None;
        }

        // s = (h + rd) / k mod n
        let s = (hash_n + &r * &private_key.data) * invert(k, &self.base_point_order);
        let s = modulo(&s, &self.base_point_order);
        if s.is_zero() {
            return None;
        }

        Some(EcdsaSignature { r, s })
    }

    /// Verifies the ECDSA `signature` of `hash`.
    /// This method assumes that the caller has made sure `public_key` is legitimate,
    /// it does not validate `public_key`.
    pub(crate) fn verify(
        &self,
        signature: &EcdsaSignature,
        hash_n: &BigInt,
        public_key: &PublicKey,
    ) -> bool {
        assert_eq!(public_key.curve_domain, self);

        // w = 1 / s mod n
        // n: base point order
        let w = invert(&signature.s, &self.base_point_order);

        // u = wh mod n
        let u = &w * hash_n;
        let u = modulo(&u, &self.base_point_order);

        // v = wr mod n
        let v = &w * &signature.r;
        let v = modulo(&v, &self.base_point_order);

        // Q = uG + vP
        let ug = self.curve.mul_point(&self.base_point, &u);
        let vp = self.curve.mul_point(&public_key.data, &v);
        let q = self.curve.add_points(&ug, &vp);
        let qx = modulo(&q.x, &self.base_point_order);

        qx == signature.r
    }
}

impl BigInt {
    pub(crate) fn from_be_bytes_with_max_bits_len(
        bytes: &[u8],
        max_bits_len: usize,
        sign: Sign,
    ) -> BigInt {
        let mut n = BigInt::from_be_bytes(bytes, sign);
        let n_bit_len = n.bit_len();
        if n_bit_len > max_bits_len {
            n = n >> (n_bit_len - max_bits_len);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::elliptic_curve::{Curve, Point};
    use crate::math::modular::modulo;

    #[test]
    fn test_ecdsa_signature() {
        // Numbers from the book Understanding Cryptography, 10.5.1

        // y^2 = x^3 + 2 * x + 2 mod 17
        let curve = Curve {
            a: BigInt::from(2),
            b: BigInt::from(2),
            p: BigInt::from(17),
        };
        let base_point = Point {
            x: BigInt::from(5),
            y: BigInt::from(1),
        };
        let base_point_order = BigInt::from(19);
        let domain = EllipticCurveDomain {
            curve,
            base_point,
            base_point_order,
            cofactor: 1,
        };

        let private_key = PrivateKey {
            data: BigInt::from(7),
            curve_domain: &domain,
        };
        let public_key = private_key.public_key();
        assert_eq!(
            public_key,
            PublicKey {
                data: Point {
                    x: BigInt::zero(),
                    y: BigInt::from(6)
                },
                curve_domain: &domain
            }
        );

        let hash = modulo(&BigInt::from(26), &domain.base_point_order);
        let k = BigInt::from(10);
        let signature = domain.sign(&hash, &private_key, &k).unwrap();
        assert_eq!(signature.r, BigInt::from(7));
        assert_eq!(signature.s, BigInt::from(17));

        assert_eq!(domain.verify(&signature, &hash, &public_key), true);
    }
}
