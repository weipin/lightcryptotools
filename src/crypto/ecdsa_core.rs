// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::elliptic_curve_domain::EllipticCurveDomain;
use crate::bigint::modular::modulo;
use crate::bigint::BigInt;
use crate::math::elliptic_curve::{invert, Point};

pub type PrivateKey = BigInt;
pub type PublicKey = Point;

pub struct EcdsaSignature {
    r: BigInt,
    s: BigInt,
}

impl EllipticCurveDomain {
    /// Returns the public key of `private_key`.
    pub(crate) fn public_key_from_private_key(&self, private_key: &PrivateKey) -> PublicKey {
        self.curve.mul_point(&self.base_point, private_key)
    }

    /// Generates a ECDSA signature of `hash` with `private_key`.
    /// `k` is a random number between 1 and n – 1.
    ///
    /// Returns None if either element of the signature (`r` or `s`) is zero.
    pub(crate) fn sign(
        &self,
        hash_n: &BigInt,
        private_key: &PrivateKey,
        k: &BigInt,
    ) -> Option<EcdsaSignature> {
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
        let s = (hash_n + &r * private_key) * invert(k, &self.base_point_order);
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
        hash: &BigInt,
        public_key: &PublicKey,
    ) -> bool {
        // w = 1 / s mod n
        // n: base point order
        let w = invert(&signature.s, &self.base_point_order);

        // u = wh mod n
        let u = &w * hash;
        let u = modulo(&u, &self.base_point_order);

        // v = wr mod n
        let v = &w * &signature.r;
        let v = modulo(&v, &self.base_point_order);

        // Q = uG + vP
        let ug = self.curve.mul_point(&self.base_point, &u);
        let vp = self.curve.mul_point(public_key, &v);
        let q = self.curve.add_points(&ug, &vp);
        let qx = modulo(&q.x, &self.base_point_order);

        qx == signature.r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::elliptic_curve::Curve;

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

        let private_key = BigInt::from(7);
        let public_key = domain.public_key_from_private_key(&private_key);
        assert_eq!(
            public_key,
            PublicKey {
                x: BigInt::zero(),
                y: BigInt::from(6)
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
