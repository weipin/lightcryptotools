// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_core::Sign;
use crate::bigint::BigInt;
use crate::crypto::ecdsa::ecdsa_key::{PrivateKey, PublicKey};
use crate::crypto::elliptic_curve_params::EllipticCurveParams;
use crate::math::modular::{invert, modulo};

#[derive(Clone, Debug)]
pub struct Signature<'a> {
    pub r: BigInt,
    pub s: BigInt,
    pub curve_params: &'a EllipticCurveParams,
}

impl<'a> Signature<'a> {
    pub fn new(r: BigInt, s: BigInt, curve_params: &'a EllipticCurveParams) -> Option<Self> {
        let signature = Signature { r, s, curve_params };
        if signature.is_valid() {
            Some(signature)
        } else {
            None
        }
    }

    fn is_valid(&self) -> bool {
        // Ensures that "0 < r < n and 0 < s < n":
        // https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/
        // https://neilmadden.blog/2022/04/25/a-few-clarifications-about-cve-2022-21449/
        //
        // Tests are done in the integration test "test_invalid_verifying".
        // Search "Invalid r, s values (== 0)".
        (self.r > BigInt::zero() && self.r < self.curve_params.base_point_order)
            && (self.s > BigInt::zero() && self.s < self.curve_params.base_point_order)
    }

    pub(crate) fn is_low_s_signature(&self) -> bool {
        self.s <= (&self.curve_params.base_point_order >> 1)
    }

    /// Returns a signature and ensures its `s` is at most the order of the base point divided by 2,
    /// (essentially restricting this value to its lower half range).
    ///
    /// For "low s" details see [BIP: 146][1]
    /// [1]: https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
    pub(crate) fn to_low_s_signature(&self) -> Signature<'a> {
        if !self.is_low_s_signature() {
            return Signature::new(
                self.r.clone(),
                &self.curve_params.base_point_order - &self.s,
                self.curve_params,
            )
            .unwrap();
        }

        self.clone()
    }
}

impl PrivateKey<'_> {
    /// Generates a ECDSA signature of `hash` with `private_key`.
    /// `k` is a random number between 1 and n – 1.
    ///
    /// Returns None if either element of the signature (`r` or `s`) is zero.
    pub(crate) fn sign(&self, hash: &BigInt, k: &BigInt) -> Option<Signature> {
        assert!(hash.bit_len() <= self.curve_params.base_point_order.bit_len());

        // `k` in [1, n - 1]
        // n: the order of the base point
        assert!(k > &BigInt::zero() && k < &self.curve_params.base_point_order);

        let curve_params = self.curve_params;
        let kg = curve_params.curve.mul_point(&curve_params.base_point, k);
        let r = kg.x;
        let r = modulo(&r, &curve_params.base_point_order);
        if r.is_zero() {
            return None;
        }

        // s = (h + rd) / k mod p
        let s = (hash + &r * &self.data) * invert(k, &curve_params.base_point_order).unwrap();
        let s = modulo(&s, &curve_params.base_point_order);
        if s.is_zero() {
            return None;
        }

        Some(Signature::new(r, s, curve_params).unwrap())
    }
}

impl PublicKey<'_> {
    /// Verifies the ECDSA `signature` of `hash`.
    /// This method assumes that the caller has made sure `public_key` is legitimate,
    /// it does not validate `public_key`.
    pub(crate) fn verify(&self, hash: &BigInt, signature: &Signature) -> bool {
        assert!(hash.bit_len() <= self.curve_params.base_point_order.bit_len());

        let curve_params = self.curve_params;

        // w = 1 / s mod n
        // n: the order of the base point
        let w = invert(&signature.s, &curve_params.base_point_order).unwrap();

        // u = wh mod n
        let u = &w * hash;
        let u = modulo(&u, &curve_params.base_point_order);

        // v = wr mod n
        let v = &w * &signature.r;
        let v = modulo(&v, &curve_params.base_point_order);

        // Q = uG + vP
        let ug = curve_params.curve.mul_point(&curve_params.base_point, &u);
        let vp = curve_params.curve.mul_point(&self.data, &v);
        let q = curve_params.curve.add_points(&ug, &vp);
        let qx = modulo(&q.x, &curve_params.base_point_order);

        qx == signature.r
    }
}

impl BigInt {
    /// Converts up to `max_bits_len` leading bits of `bytes` to an integer.
    pub(crate) fn from_be_bytes_with_max_bits_len(
        bytes: &[u8],
        max_bits_len: usize,
        sign: Sign,
    ) -> BigInt {
        debug_assert!(max_bits_len > 0);

        if bytes.len() * 8 <= max_bits_len {
            return BigInt::from_be_bytes(bytes, sign);
        }

        let bytes_len = max_bits_len / 8;
        let bits_remaining_len = max_bits_len % 8;
        if bits_remaining_len == 0 {
            BigInt::from_be_bytes(&bytes[0..bytes_len], sign)
        } else {
            let mut n = BigInt::from_be_bytes(&bytes[0..=bytes_len], sign);
            n = n >> (8 - bits_remaining_len);
            n
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elliptic_curve_params::EllipticCurveParams;
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
        let curve_params = EllipticCurveParams {
            curve,
            base_point,
            base_point_order,
            cofactor: 1,
        };

        let private_key = PrivateKey::new(BigInt::from(7), &curve_params).unwrap();
        let public_key = private_key.public_key();
        assert_eq!(
            public_key,
            PublicKey::new(
                Point {
                    x: BigInt::zero(),
                    y: BigInt::from(6)
                },
                &curve_params
            )
            .unwrap()
        );

        let hash = modulo(&BigInt::from(26), &curve_params.base_point_order);
        let k = BigInt::from(10);
        let signature = private_key.sign(&hash, &k).unwrap();
        assert_eq!(signature.r, BigInt::from(7));
        assert_eq!(signature.s, BigInt::from(17));

        assert_eq!(public_key.verify(&hash, &signature), true);
    }

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
            let signature = Signature::new(BigInt::one(), s1, secp256k1).unwrap();
            assert_eq!(signature.to_low_s_signature().s, s2);
        }
    }

    #[test]
    fn test_ecdsa_secp256k1_signing_and_verifying_common() {
        let secp256k1 = secp256k1();

        let hash_hex = "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a";
        let d_hex = "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f";
        // this `k` isn't deterministic but a random number
        let k_hex = "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a";
        let signature_hex = concat!(
            "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795",
            "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e"
        );

        let d = BigInt::from_hex(d_hex).unwrap();
        let private_key = PrivateKey::new(d.clone(), secp256k1).unwrap();
        let public_key = private_key.public_key();
        let hash_n = BigInt::from_hex(hash_hex).unwrap();
        let k = BigInt::from_hex(k_hex).unwrap();
        let signature = private_key.sign(&hash_n, &k).unwrap();

        // sign and verify
        let hex = signature.to_p1363_hex();
        assert_eq!(hex, signature_hex);
        assert!(public_key.verify(&hash_n, &signature));

        // verifying should fail with wrong public key
        let wrong_private_key = PrivateKey::new(&d + BigInt::one(), secp256k1).unwrap();
        let wrong_public_key = wrong_private_key.public_key();
        assert!(!wrong_public_key.verify(&hash_n, &signature));

        // verifying should fail with wrong hash
        assert!(!public_key.verify(&(&hash_n + BigInt::one()), &signature));

        // verifying should fail with wrong signature
        let wrong_signature =
            Signature::new(BigInt::from(2), BigInt::from(2), secp256k1).unwrap();
        assert!(!public_key.verify(&hash_n, &wrong_signature));
    }

    #[test]
    fn sign_and_verify() {
        const GEN_SIZE: usize = 16;
        const TEST_NUMBER: u64 = 10;

        fn prop(h_hex: HexString, d_hex: HexString, k_hex: HexString) -> bool {
            let secp256k1 = secp256k1();

            let hash_n = BigInt::from_hex(&h_hex.0).unwrap();
            let private_key =
                PrivateKey::new(BigInt::from_hex(&d_hex.0).unwrap(), secp256k1).unwrap();
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
    fn test_from_be_bytes_with_max_bits_len() {
        #[rustfmt::skip]
        let data = [
            (&[u8::MAX][..], 17, BigInt::from(255)),
            (&[u8::MAX][..], 16, BigInt::from(255)),
            (&[u8::MAX][..], 15, BigInt::from(255)),
            (&[u8::MAX][..], 8, BigInt::from(255)),
            (&[u8::MAX][..], 7, BigInt::from(255 >> 1)),
            (&[u8::MAX][..], 6, BigInt::from(255 >> 2)),
            (&[u8::MAX][..], 5, BigInt::from(255 >> 3)),
            (&[u8::MAX][..], 4, BigInt::from(255 >> 4)),
            (&[u8::MAX][..], 3, BigInt::from(255 >> 5)),
            (&[u8::MAX][..], 2, BigInt::from(255 >> 6)),
            (&[u8::MAX][..], 1, BigInt::from(255 >> 7)),
            (&[1_u8][..], 1, BigInt::from(0)),
            (&[1_u8][..], 5, BigInt::from(0)),
            (&[1_u8][..], 7, BigInt::from(0)),
            (&[1_u8][..], 8, BigInt::from(1)),
            (&[1_u8][..], 9, BigInt::from(1)),
            (&[128_u8, 1][..], 1, BigInt::from(1)),
            (&[128_u8, 1][..], 3, BigInt::from(1 << 2)),
            (&[128_u8, 1][..], 5, BigInt::from(1 << 4)),
            (&[128_u8, 1][..], 7, BigInt::from(1 << 6)),
            (&[128_u8, 1][..], 8, BigInt::from(1 << 7)),
            (&[128_u8, 1][..], 9, BigInt::from(256)),
            (&[128_u8, 1][..], 10, BigInt::from(256 << 1)),
            (&[128_u8, 1][..], 12, BigInt::from(256 << 3)),
            (&[128_u8, 1][..], 14, BigInt::from(256 << 5)),
            (&[128_u8, 1][..], 15, BigInt::from(256 << 6)),
            (&[128_u8, 1][..], 16, BigInt::from((256 << 7) + 1)),
            (&[128_u8, 1][..], 17, BigInt::from((256 << 7) + 1)),
            (&[
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1_u8,
            ][..], 256, BigInt::from(1)),
            (&[
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1_u8, 66,
            ][..], 256, BigInt::from(1)),
        ];

        for (bytes, max_bits_len, n) in data {
            assert_eq!(
                BigInt::from_be_bytes_with_max_bits_len(bytes, max_bits_len, Sign::Positive),
                n
            );
        }
    }
}
