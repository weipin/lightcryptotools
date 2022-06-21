// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::curves::*;
use devtools::path::integration_testing_data_path;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
use lightcryptotools::crypto::ecdsa::{
    recover_public_keys_from_signature, recover_public_keys_from_signature_with_options,
    sign_with_options, PrivateKey, RecoveryOptions, SignatureRecoveryId, SigningOptions,
};
use lightcryptotools::crypto::hash::{Sha256, UnkeyedHash};
use lightcryptotools::crypto::{secp256k1, EllipticCurveParams};
use lightcryptotools::random::generator::get_os_random_bytes;
use serde_json::Value;
use std::fs::File;

#[test]
#[ignore]
fn test_curve_w25519_enforcing_low_s() {
    test_curve_w25519(true);
}

#[test]
#[ignore]
fn test_curve_w25519_not_enforcing_low_s() {
    test_curve_w25519(false);
}

#[test]
#[ignore]
fn test_recovery_enforcing_low_s() {
    test_recovery(true);
}

#[test]
#[ignore]
fn test_recovery_not_enforcing_low_s() {
    test_recovery(false);
}

#[test]
#[ignore]
fn test_recovery_with_curves_enforcing_low_s() {
    test_recovery_with_curves(true);
}

#[test]
#[ignore]
fn test_recovery_with_curves_not_enforcing_low_s() {
    test_recovery_with_curves(false);
}

/// Tests against a curve whose cofactor == 8.
/// The signature of the case has a "higher x" recovery id.
fn test_curve_w25519(enforce_low_s: bool) {
    // w25519's cofactor is 8
    let curve = w25519();

    let hash_hex = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
    let hash = hex_to_bytes(hash_hex).unwrap();
    let d = BigInt::from(1);

    let private_key = PrivateKey::new(d, &curve).unwrap();
    let public_key = private_key.public_key();
    let (signature, recovery_id) = sign_with_options(
        &hash,
        &private_key,
        &SigningOptions {
            enforce_low_s,
            strict_hash_byte_length: false,
            employ_extra_random_data: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(recovery_id, SignatureRecoveryId::HighXOddY);

    // with recovery_id
    let public_keys = recover_public_keys_from_signature_with_options(
        &signature,
        &hash,
        Some(recovery_id),
        &RecoveryOptions {
            strict_hash_byte_length: false,
        },
    )
    .unwrap();
    assert_eq!(public_keys.len(), 1);
    assert_eq!(public_keys[0], public_key);

    // without recovery_id
    let public_keys = recover_public_keys_from_signature_with_options(
        &signature,
        &hash,
        None,
        &RecoveryOptions {
            strict_hash_byte_length: false,
        },
    )
    .unwrap();
    assert_eq!(public_keys.len(), 2);
    assert_eq!(public_keys[1], public_key);
}

/// Tests cases from ecdsa.json
fn test_recovery(enforce_low_s: bool) {
    let secp256k1 = secp256k1();

    let path = integration_testing_data_path("crypto/secp256k1/noble-secp256k1/ecdsa.json");
    let file = File::open(path).unwrap();
    let root: Value = serde_json::from_reader(file).unwrap();
    let value_vec = root["valid"].as_array().unwrap();
    for value in value_vec {
        let d_hex = value["d"].as_str().unwrap();
        let m_hex = value["m"].as_str().unwrap();
        let m = hex_to_bytes(m_hex).unwrap();

        // Ignore zero hash, for recovery doesn't allow zero hash input
        if BigInt::from_hex(m_hex).unwrap().is_zero() {
            continue;
        }

        let private_key = PrivateKey::new(BigInt::from_hex(d_hex).unwrap(), secp256k1).unwrap();
        let public_key = private_key.public_key();

        let (signature, recovery_id) = sign_with_options(
            &m,
            &private_key,
            &SigningOptions {
                enforce_low_s,
                employ_extra_random_data: false,
                ..Default::default()
            },
        )
        .unwrap();

        // With recovery_id
        let public_keys1 =
            recover_public_keys_from_signature(&signature, &m, Some(recovery_id)).unwrap();
        assert!(public_keys1.contains(&public_key));

        // Without recovery_id
        let public_keys2 = recover_public_keys_from_signature(&signature, &m, None).unwrap();
        assert!(public_keys2.contains(&public_key));

        assert!(public_keys2.len() > public_keys1.len());
    }
}

fn test_recovery_with_curves(enforce_low_s: bool) {
    let curves = vec![
        nist_p256(),
        brainpool_p256r1(),
        brainpool_p320r1(),
        brainpool_p384r1(),
        brainpool_p512r1(),
        secp224r1(),
        secp256r1(),
        secp384r1(),
        secp521r1(),
        w25519(),
    ];

    for curve in curves {
        test_recovery_with_curve(&curve, enforce_low_s);
    }
}

fn test_recovery_with_curve(curve: &EllipticCurveParams, enforce_low_s: bool) {
    let key_bytes = get_os_random_bytes(12).unwrap();
    let d = BigInt::from_hex(bytes_to_lower_hex(&key_bytes)).unwrap();
    let private_key = PrivateKey::new(d, curve).unwrap();
    let public_key = private_key.public_key();

    let message_bytes = get_os_random_bytes(32).unwrap();
    let hash = Sha256::new().digest(message_bytes);

    let (signature, recovery_id) = sign_with_options(
        &hash,
        &private_key,
        &SigningOptions {
            enforce_low_s,
            strict_hash_byte_length: false,
            employ_extra_random_data: false,
            ..Default::default()
        },
    )
    .unwrap();

    // With recovery_id
    let public_keys = recover_public_keys_from_signature_with_options(
        &signature,
        &hash,
        Some(recovery_id),
        &RecoveryOptions {
            strict_hash_byte_length: false,
        },
    )
    .unwrap();
    assert!(public_keys.contains(&public_key));

    // Without recovery_id
    let public_keys = recover_public_keys_from_signature_with_options(
        &signature,
        &hash,
        None,
        &RecoveryOptions {
            strict_hash_byte_length: false,
        },
    )
    .unwrap();
    assert!(public_keys.contains(&public_key));
}
