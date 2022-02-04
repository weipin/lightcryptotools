// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Gets cryptographically secure random bytes from operating system.
//!
//! # Examples
//!
//! cargo run --bin randombytes -- 16

use lightcryptotools::crypto::bytes_to_hex;
use lightcryptotools::random::get_os_random_bytes;

fn main() {
    let bytes_len = std::env::args()
        .nth(1)
        .expect("Error: the parameter is missing");
    let bytes_len = bytes_len.parse().expect("Error: expecting an integer");

    match get_os_random_bytes(bytes_len) {
        Ok(bytes) => {
            let hex = bytes_to_hex(&bytes);
            println!("0x{hex}");
        }
        Err(err) => {
            println!("Error: {err}");
        }
    }
}
