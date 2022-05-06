// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Numbers from rfc6979#appendix-A.2.5:
//! https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.5

use crate::curves::nist_p256;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::ecdsa::{sign_with_options, verify, PrivateKey, SigningOptions};
use ring::digest;
use ring::hmac::{HMAC_SHA1_FOR_LEGACY_USE_ONLY, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512};

#[test]
fn test_ecdsa_p256_sha1_sign() {
    let curve = nist_p256();
    let d =
        BigInt::from_hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
            .unwrap();
    let private_key = PrivateKey::new(d, &curve).unwrap();
    let signature_expected = concat!(
        "61340c88c3aaebeb4f6d667f672ca9759a6ccaa9fa8811313039ee4a35471d32",
        "6d7f147dac089441bb2e2fe8f7a3fa264b9c475098fdcf6e00d7c996e1b8b7eb"
    );

    let message = b"sample";
    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(message);
    let digest = context.finish();
    let hash = digest.as_ref();

    let signature = sign_with_options(
        hash,
        &private_key,
        &SigningOptions {
            hmac_hash_algorithm: &HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            enforce_low_s: false,
            strict_hash_byte_length: false,
            employ_extra_random_data: false,
        },
    )
    .unwrap();
    assert_eq!(signature.to_p1363_hex(), signature_expected);

    let public_key = private_key.public_key();
    assert!(verify(hash, &signature, &public_key).unwrap());
}

#[test]
fn test_ecdsa_p256_sha256_sign() {
    let curve = nist_p256();
    let d =
        BigInt::from_hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
            .unwrap();
    let private_key = PrivateKey::new(d, &curve).unwrap();
    let signature_expected = concat!(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    );

    let message = b"sample";
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(message);
    let digest = context.finish();
    let hash = digest.as_ref();

    let signature = sign_with_options(
        hash,
        &private_key,
        &SigningOptions {
            hmac_hash_algorithm: &HMAC_SHA256,
            enforce_low_s: false,
            employ_extra_random_data: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(signature.to_p1363_hex(), signature_expected);

    let public_key = private_key.public_key();
    assert!(verify(hash, &signature, &public_key).unwrap());
}

#[test]
fn test_ecdsa_p256_sha384_sign() {
    let curve = nist_p256();
    let d =
        BigInt::from_hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
            .unwrap();
    let private_key = PrivateKey::new(d, &curve).unwrap();
    let signature_expected = concat!(
        "0eafea039b20e9b42309fb1d89e213057cbf973dc0cfc8f129edddc800ef7719",
        "4861f0491e6998b9455193e34e7b0d284ddd7149a74b95b9261f13abde940954"
    );

    let message = b"sample";
    let mut context = digest::Context::new(&digest::SHA384);
    context.update(message);
    let digest = context.finish();
    let hash = digest.as_ref();

    let signature = sign_with_options(
        hash,
        &private_key,
        &SigningOptions {
            hmac_hash_algorithm: &HMAC_SHA384,
            enforce_low_s: false,
            strict_hash_byte_length: false,
            employ_extra_random_data: false,
        },
    )
    .unwrap();
    assert_eq!(signature.to_p1363_hex(), signature_expected);

    let public_key = private_key.public_key();
    assert!(verify(hash, &signature, &public_key).unwrap());
}

#[test]
fn test_ecdsa_p256_sha512_sign() {
    let curve = nist_p256();
    let d =
        BigInt::from_hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
            .unwrap();
    let private_key = PrivateKey::new(d, &curve).unwrap();
    let signature_expected = concat!(
        "8496a60b5e9b47c825488827e0495b0e3fa109ec4568fd3f8d1097678eb97f00",
        "2362ab1adbe2b8adf9cb9edab740ea6049c028114f2460f96554f61fae3302fe"
    );

    let message = b"sample";
    let mut context = digest::Context::new(&digest::SHA512);
    context.update(message);
    let digest = context.finish();
    let hash = digest.as_ref();

    let signature = sign_with_options(
        hash,
        &private_key,
        &SigningOptions {
            hmac_hash_algorithm: &HMAC_SHA512,
            enforce_low_s: false,
            strict_hash_byte_length: false,
            employ_extra_random_data: false,
        },
    )
    .unwrap();
    assert_eq!(signature.to_p1363_hex(), signature_expected);

    let public_key = private_key.public_key();
    assert!(verify(hash, &signature, &public_key).unwrap());
}
