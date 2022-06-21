// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Seeks a private key for an address with the specified prefix.
//! WARNING: This should only be viewed as a toy program!
//!
//! # Examples
//!
//! cargo run --bin eoa_gen_vanity_address -- 3C

extern crate core;

use lightcryptotools::blockchain::ethereum::account::{
    EoaPrivateKey, EoaPrivateKeyData, EOA_PRIVATE_KEY_DATA_BYTE_LENGTH,
};
use lightcryptotools::crypto::codecs::bytes_to_lower_hex;
use lightcryptotools::random::generator::get_os_random_bytes;
use std::time::Instant;

fn main() {
    let prefix = std::env::args()
        .nth(1)
        .expect("Error: the parameter is missing");

    assert!(
        !prefix.is_empty() && prefix.len() < 40,
        "Error: invalid prefix length"
    );

    if !prefix
        .chars()
        .all(|c| matches!(c, '0'..='9' | 'a'..='f' | 'A'..='F'))
    {
        panic!("Error: a prefix should only contain characters in [0-9a-fA-F]")
    }

    let estimated_count = 32_usize.pow(prefix.len() as u32);
    let mut count = 0_usize;
    let start = Instant::now();
    let mut report_start = Instant::now();
    loop {
        count += 1;
        if report_start.elapsed().as_secs() > 3 {
            let percent = count * 100 / estimated_count;
            let count_per_second = count / start.elapsed().as_secs() as usize;
            println!("> {count}, {percent}%, {count_per_second}/s");
            report_start = Instant::now();
        }

        let key_bytes = get_os_random_bytes(EOA_PRIVATE_KEY_DATA_BYTE_LENGTH as u32)
            .expect("failed to generate random bytes");
        let key_data: EoaPrivateKeyData = key_bytes.try_into().unwrap();
        let checksummed_hex = EoaPrivateKey::new(key_data)
            .unwrap()
            .public_key()
            .address()
            .to_checksummed_hex();
        if !checksummed_hex.starts_with(&prefix) {
            continue;
        }

        // found
        println!("=====================");
        println!("Vanity Address Found!");
        println!("=====================");
        println!("public address: 0x{checksummed_hex}");
        println!("private key: 0x{}", bytes_to_lower_hex(&key_data));
        break;
    }
}
