// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::ecdsa_core::PrivateKey;
use super::elliptic_curve_domain::EllipticCurveDomain;
use crate::crypto::ecdsa_core::PublicKey;

pub fn public_key_from_private_key(
    private_key: &PrivateKey,
    curve_domain: &EllipticCurveDomain,
) -> PublicKey {
    curve_domain.public_key_from_private_key(private_key)
}
