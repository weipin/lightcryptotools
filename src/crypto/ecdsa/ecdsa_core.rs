// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::Sign;
use crate::bigint::BigInt;
use crate::crypto::ecdsa::ecdsa_key::{PrivateKey, PublicKey};
use crate::crypto::elliptic_curve_domain::EllipticCurveDomain;
use crate::math::modular::{invert, modulo};

#[derive(Clone, Debug)]
pub struct Signature<'a> {
    pub r: BigInt,
    pub s: BigInt,
    pub curve_domain: &'a EllipticCurveDomain,
}

impl Signature<'_> {
    pub fn to_hex(&self) -> String {
        assert!(self.r < self.curve_domain.base_point_order);
        assert!(self.s < self.curve_domain.base_point_order);

        let hex_len = self.curve_domain.base_point_order.byte_len() * 2;
        let r_hex = self.r.to_hex();
        let s_hex = self.s.to_hex();

        format!("{r_hex:0>hex_len$}{s_hex:0>hex_len$}")
    }
}

impl PrivateKey<'_> {
    /// Generates a ECDSA signature of `hash_n` with `private_key`.
    /// `k` is a random number between 1 and n – 1.
    ///
    /// Returns None if either element of the signature (`r` or `s`) is zero.
    pub(crate) fn sign(&self, hash_n: &BigInt, k: &BigInt) -> Option<Signature> {
        assert!(hash_n.bit_len() <= self.curve_domain.base_point_order.bit_len());

        // `k` in [1, n - 1]
        // n: base point order
        assert!(k > &BigInt::zero() && k < &self.curve_domain.base_point_order);

        let curve_domain = self.curve_domain;
        let kg = curve_domain.curve.mul_point(&curve_domain.base_point, k);
        let r = kg.x;
        let r = modulo(&r, &curve_domain.base_point_order);
        if r.is_zero() {
            return None;
        }

        // s = (h + rd) / k mod p
        let s = (hash_n + &r * &self.data) * invert(k, &curve_domain.base_point_order);
        let s = modulo(&s, &curve_domain.base_point_order);
        if s.is_zero() {
            return None;
        }

        Some(Signature { r, s, curve_domain })
    }
}

impl PublicKey<'_> {
    /// Verifies the ECDSA `signature` of `hash`.
    /// This method assumes that the caller has made sure `public_key` is legitimate,
    /// it does not validate `public_key`.
    pub(crate) fn verify(&self, hash_n: &BigInt, signature: &Signature) -> bool {
        let curve_domain = self.curve_domain;

        // w = 1 / s mod n
        // n: base point order
        let w = invert(&signature.s, &curve_domain.base_point_order);

        // u = wh mod n
        let u = &w * hash_n;
        let u = modulo(&u, &curve_domain.base_point_order);

        // v = wr mod n
        let v = &w * &signature.r;
        let v = modulo(&v, &curve_domain.base_point_order);

        // Q = uG + vP
        let ug = curve_domain.curve.mul_point(&curve_domain.base_point, &u);
        let vp = curve_domain.curve.mul_point(&self.data, &v);
        let q = curve_domain.curve.add_points(&ug, &vp);
        let qx = modulo(&q.x, &curve_domain.base_point_order);

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
    use crate::crypto::elliptic_curve_domain::EllipticCurveDomain;
    use crate::crypto::secp256k1;
    use crate::math::elliptic_curve::{Curve, Point};
    use crate::testing_tools::quickcheck::HexString;
    use quickcheck::{Gen, QuickCheck};

    #[test]
    fn test_ecdsa_signing_with_textbook_numbers() {
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
        let signature = private_key.sign(&hash, &k).unwrap();
        assert_eq!(signature.r, BigInt::from(7));
        assert_eq!(signature.s, BigInt::from(17));

        assert_eq!(public_key.verify(&hash, &signature), true);
    }

    #[test]
    fn sign_and_verify() {
        const GEN_SIZE: usize = 16;
        const TEST_NUMBER: u64 = 10;

        fn prop(h_hex: HexString, d_hex: HexString, k_hex: HexString) -> bool {
            let secp256k1 = secp256k1();

            let hash_n = BigInt::from_hex(&h_hex.0).unwrap();
            let private_key = PrivateKey {
                data: BigInt::from_hex(&d_hex.0).unwrap(),
                curve_domain: secp256k1,
            };
            if private_key.data.is_zero() {
                return true; // ignore
            }
            let public_key = private_key.public_key();
            let k = BigInt::from_hex(&k_hex.0).unwrap();
            if k.is_zero() {
                return true;
            }

            let signature = private_key.sign(&hash_n, &k).unwrap();
            let success = public_key.verify(&hash_n, &signature);
            let failure = public_key.verify(&(&hash_n + BigInt::one()), &signature);

            success && !failure
        }

        QuickCheck::new()
            .gen(Gen::new(GEN_SIZE))
            .tests(TEST_NUMBER)
            .quickcheck(prop as fn(HexString, HexString, HexString) -> bool)
    }

    #[test]
    fn test_ecdsa_secp256k1_signing_cases() {
        let secp256k1 = secp256k1();

        // (hash, d, k, signature)
        let data = [(
            "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a",
            "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f",
            "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a", // this `k` isn't deterministic but a random number
            concat!(
                "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795",
                "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e"
            ),
        )];
        for (hash_hex, d_hex, k_hex, signature_hex) in data {
            let private_key = PrivateKey {
                data: BigInt::from_hex(d_hex).unwrap(),
                curve_domain: secp256k1,
            };
            let hash_d = BigInt::from_hex(hash_hex).unwrap();
            let k = BigInt::from_hex(k_hex).unwrap();
            let signature = private_key.sign(&hash_d, &k).unwrap();

            let hex = signature.to_hex();
            assert_eq!(hex, signature_hex);
        }
    }
}
