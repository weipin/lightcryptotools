// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Generates EOA public address from EOA private key.
//!
//! # Examples
//!
//! cargo run --example eoa_key_to_address -- c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4
//! cargo run --example eoa_key_to_address -- 0xc85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4

use lightcryptotools::blockchain::ethereum::account::{EoaPrivateKey, EoaPrivateKeyData};
use lightcryptotools::crypto::codecs::hex_to_bytes;

fn main() {
    let key_hex = std::env::args()
        .nth(1)
        .expect("Error: the parameter is missing");
    let key_hex = key_hex.strip_prefix("0x").unwrap_or(&key_hex);

    let key_bytes = hex_to_bytes(key_hex).expect("invalid key hex");
    let key_data: EoaPrivateKeyData = key_bytes.try_into().expect("invalid key data");
    let eoa_private_key = EoaPrivateKey::new(key_data).expect("invalid private key");
    let eoa_public_key = eoa_private_key.public_key();
    let address = eoa_public_key.address();

    println!("{address}");
}
