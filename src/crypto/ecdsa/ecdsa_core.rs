// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::ecdsa_key::{PrivateKey, PublicKey};
use crate::bigint::bigint_core::Sign;
use crate::bigint::BigInt;
use crate::crypto::elliptic_curve_params::EllipticCurveParams;
use crate::math::modular::{invert, modulo};
use std::fmt;
use std::fmt::Display;

#[derive(Clone, Debug)]
pub struct Signature<'a> {
    pub r: BigInt,
    pub s: BigInt,
    pub curve_params: &'a EllipticCurveParams,
}

impl<'a> Signature<'a> {
    pub fn new(r: BigInt, s: BigInt, curve_params: &'a EllipticCurveParams) -> Option<Self> {
        let signature = Signature { r, s, curve_params };
        signature.is_valid().then_some(signature)
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
        debug_assert!(self.curve_params.base_point_order.is_odd());

        // LOW_S: ...is at most the curve order divided by 2...
        // See BIP146: https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#LOW_S
        self.s <= (&self.curve_params.base_point_order >> 1)
    }
}

impl PrivateKey<'_> {
    /// Generates a ECDSA signature and the recovery id of `hash` with the private key `self`.
    ///
    /// # Parameters
    ///
    /// * `k`: a random number between 1 and n – 1.
    ///
    /// Returns None if either element of the signature (`r` or `s`) is zero.
    pub(crate) fn sign(
        &self,
        hash: &BigInt,
        k: &BigInt,
    ) -> Option<(Signature, SignatureRecoveryId)> {
        assert!(hash.bit_len() <= self.curve_params.base_point_order.bit_len());

        // `k` in [1, n - 1]
        // n: the order of the base point
        assert!(k > &BigInt::zero() && k < &self.curve_params.base_point_order);

        let curve_params = self.curve_params;
        let kg = curve_params.curve.mul_point(&curve_params.base_point, k);

        let r = modulo(&kg.x, &curve_params.base_point_order);
        if r.is_zero() {
            return None;
        }

        // s = (h + rd) / k mod p
        let s = (hash + &r * &self.data) * invert(k, &curve_params.base_point_order).unwrap();
        let s = modulo(&s, &curve_params.base_point_order);
        if s.is_zero() {
            return None;
        }

        // Creates a `SignatureRecoveryId` through bitwise operations.
        //
        // * `<< 1`: the most significant bit represents "low/high x".
        // * `as u8`: casting a bool into an integer, true will be 1 and false will be 0.
        // * `kg.x != r`: if true, `kg.x` is "high x".
        //   `r` is kg.x modulo n. When kg.x is between n and p (kg.x >= n),
        //   `r` is reduced to `kg.x - j*n`, where j is in [1, cofactor].
        // * `kg.y.is_odd() as u8`: the least significant bit represents "even/odd y".
        let recovery_id =
            SignatureRecoveryId::from_u8(((kg.x != r) as u8) << 1 | (kg.y.is_odd() as u8))
                .unwrap();

        Some((Signature::new(r, s, curve_params).unwrap(), recovery_id))
    }
}

impl PublicKey<'_> {
    /// Verifies the ECDSA `signature` of `hash`.
    /// This method assumes that the caller has made sure `public_key` is legitimate,
    /// it does not validate `public_key`.
    ///
    /// # Notes
    ///
    /// This function allows `hash` to be zero. If `hash` is zero, for any public key Q(x, y),
    /// a signature (x, x) will pass the verification. For an example,
    /// see the testcase "test_verify_zero_hash" below.
    ///
    /// With this in mind, the higher level verifying functions in this library (ecdsa_verifying.rs)
    /// don't allow zero hash by default.
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

/// Returns true if the hash length in bits equals the order of the base point in bits.
pub(crate) fn hash_length_matches_base_point_order(
    hash_byte_length: usize,
    curve_params: &EllipticCurveParams,
) -> bool {
    debug_assert_eq!(
        curve_params.base_point_order.bit_len() % u8::BITS as usize,
        0,
        "The bit length of the order of the base point is not 1-byte aligned."
    );

    hash_byte_length * u8::BITS as usize == curve_params.base_point_order.bit_len()
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

/// Bit flags determine the viable public keys that can be recovered from a signature.
///
/// LowX: R.x < base_point_order
/// HighX: R.x >= base_point_order
/// EvenY: R.y is even
/// OddY: R.y is odd
///
/// * R: curve point R = k * G
///
/// # Details
///
/// "...Given an ECDSA signature (r, s) and EC domain parameters, it is generally possible to determine
/// the public key Q, at least to within a small number of choices...
/// Potentially, several candidate public keys can be recovered from a signature. At a small cost, the
/// signer can generate the ECDSA signature in such a way that only one of the candidate public keys
/// is viable..."
///
/// For details, see SEC 1 Ver. 2.0[1], 4.1.6 Public Key Recovery Operation
///
/// [1]: http://www.secg.org/SEC1-Ver-2.0.pdf
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureRecoveryId {
    LowXEvenY = 0,
    LowXOddY = 1,
    HighXEvenY = 2,
    HighXOddY = 3,
}

impl SignatureRecoveryId {
    pub(crate) fn from_u8(n: u8) -> Option<SignatureRecoveryId> {
        Some(match n {
            0 => SignatureRecoveryId::LowXEvenY,
            1 => SignatureRecoveryId::LowXOddY,
            2 => SignatureRecoveryId::HighXEvenY,
            3 => SignatureRecoveryId::HighXOddY,
            _ => return None,
        })
    }

    pub(crate) fn y_parity(&self) -> YParity {
        match self {
            SignatureRecoveryId::LowXOddY | SignatureRecoveryId::HighXOddY => YParity::Odd,
            SignatureRecoveryId::LowXEvenY | SignatureRecoveryId::HighXEvenY => YParity::Even,
        }
    }
}

/// The parity (0 for even, 1 for odd) of the y-value of a secp256k1 signature
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum YParity {
    Even = 0,
    Odd = 1,
}

impl YParity {
    pub(crate) fn from_u8(n: u8) -> Option<YParity> {
        Some(match n {
            0 => YParity::Even,
            1 => YParity::Odd,
            _ => return None,
        })
    }
}

impl Display for YParity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YParity::Even => {
                write!(f, "{} (even)", *self as u8)
            }
            YParity::Odd => {
                write!(f, "{} (odd)", *self as u8)
            }
        }
    }
}

pub(crate) const EMPTY_HASH_NOT_ALLOWED_ERROR_DISPLAY: &str = "Empty hash is not allowed";
pub(crate) const ZERO_HASH_NOT_ALLOWED_ERROR_DISPLAY: &str = "Zero hash is not allowed";
pub(crate) const HASH_BIT_LENGTH_DOES_NOT_MATCH_BASE_POINT_ORDER_ERROR_DISPLAY: &str =
    "Hash length in bits doesn't equal to the order of the base point in bits";

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
        let (signature, _) = private_key.sign(&hash, &k).unwrap();
        assert_eq!(signature.r, BigInt::from(7));
        assert_eq!(signature.s, BigInt::from(17));

        assert_eq!(public_key.verify(&hash, &signature), true);
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
        let (signature, _) = private_key.sign(&hash_n, &k).unwrap();

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
            let d = BigInt::from_hex(&d_hex.0).unwrap();
            if d.is_zero() {
                return true; // ignore zero -- invalid private key
            }
            let private_key = PrivateKey::new(d, secp256k1).unwrap();
            if private_key.data.is_zero() {
                return true; // ignore
            }
            let public_key = private_key.public_key();
            let k = BigInt::from_hex(&k_hex.0).unwrap();
            if k.is_zero() {
                return true;
            }

            let (signature, _) = private_key.sign(&hash_n, &k).unwrap();
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
    fn test_verify_zero_hash() {
        let curve = secp256k1();
        let private_key1 = PrivateKey::new(BigInt::from(1), curve).unwrap();
        let public_key1 = private_key1.public_key();
        let private_key2 = PrivateKey::new(BigInt::from(2), curve).unwrap();
        let public_key2 = private_key2.public_key();
        let hash_n = BigInt::zero();

        let fake_signature = Signature::new(
            public_key1.data.x.clone(),
            public_key1.data.x.clone(),
            curve,
        )
        .unwrap();
        assert!(public_key1.verify(&hash_n, &fake_signature));

        let fake_signature = Signature::new(
            public_key2.data.x.clone(),
            public_key2.data.x.clone(),
            curve,
        )
        .unwrap();
        assert!(public_key2.verify(&hash_n, &fake_signature));
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

    #[test]
    fn test_is_low_s_signature() {
        let curve = secp256k1();

        // curve order divided by 2
        let order_div_2 = BigInt::from_hex(
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
        )
        .unwrap();
        assert_eq!(&curve.base_point_order >> 1, order_div_2);

        // (s, is_low_s)
        let data = [
            (order_div_2.clone(), true),
            (&order_div_2 - BigInt::one(), true),  // -1
            (&order_div_2 + BigInt::one(), false), // +1
        ];

        for (s, is_low_s) in data {
            let signature = Signature {
                r: BigInt::from(1),
                s,
                curve_params: curve,
            };
            assert_eq!(signature.is_low_s_signature(), is_low_s);
        }
    }
}
