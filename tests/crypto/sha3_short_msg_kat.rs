// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::path::integration_testing_data_path;
use lightcryptotools::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
use lightcryptotools::crypto::hash::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, UnkeyedHash};
use std::fs::File;
use std::io;
use std::io::BufRead;

#[test]
#[ignore]
fn test_sha3_short_msg_kat() {
    test_sha3_short_msg_kat_core("ShortMsgKAT_SHA3-224.txt", &mut Sha3_224::new());
    test_sha3_short_msg_kat_core("ShortMsgKAT_SHA3-256.txt", &mut Sha3_256::new());
    test_sha3_short_msg_kat_core("ShortMsgKAT_SHA3-384.txt", &mut Sha3_384::new());
    test_sha3_short_msg_kat_core("ShortMsgKAT_SHA3-512.txt", &mut Sha3_512::new());
}

fn test_sha3_short_msg_kat_core<T: UnkeyedHash>(data_filename: &str, hasher: &mut T) {
    let path = integration_testing_data_path(&format!("crypto/sha3/xkcp/{data_filename}"));
    let file = File::open(path).unwrap();
    let mut lines = io::BufReader::new(file).lines();
    let mut count = 0;

    loop {
        match lines.next() {
            Some(Ok(line)) => {
                if !line.starts_with("Len =") {
                    continue;
                }

                let bit_len: usize = line
                    .split('=')
                    .skip(1)
                    .next()
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                // Ignores cases with non-byte-aligned message
                if bit_len % 8 != 0 {
                    continue;
                }
                let byte_len = bit_len / 8;

                let msg_line = lines.next().unwrap().unwrap();
                let msg_hex = msg_line.split('=').skip(1).next().unwrap().trim();
                let md_line = lines.next().unwrap().unwrap();
                let md_hex = md_line
                    .split('=')
                    .skip(1)
                    .next()
                    .unwrap()
                    .trim()
                    .to_lowercase();
                let digest = hasher.digest(&hex_to_bytes(msg_hex).unwrap()[..byte_len]);
                assert_eq!(bytes_to_lower_hex(&digest), md_hex);
                count += 1;
            }
            None => {
                break;
            }
            _ => {
                continue;
            }
        }
    }
    // Ensures that we indeed have enough cases tested without some parsing failures
    assert!(count > 200);
}
