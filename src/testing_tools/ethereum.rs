// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::blockchain::ethereum::account::{EoaPrivateKey, EoaPrivateKeyData};
use crate::crypto::codecs::hex_to_bytes;

pub(crate) fn private_key_hex_to_address(private_key_hex: &str) -> String {
    let key_bytes = hex_to_bytes(private_key_hex).unwrap();
    let key_data: EoaPrivateKeyData = key_bytes.try_into().unwrap();
    let eoa_private_key = EoaPrivateKey::new(key_data).unwrap();
    let eoa_public_key = eoa_private_key.public_key();
    let address = eoa_public_key.address();

    format!("{address}")
}
