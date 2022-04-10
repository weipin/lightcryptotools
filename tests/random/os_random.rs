// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use lightcryptotools::random::generator::get_os_random_bytes;

#[test]
fn get_os_random_bytes_0() {
    let bytes = get_os_random_bytes(0).unwrap();
    assert_eq!(bytes.len(), 0);
}

#[test]
fn get_os_random_bytes_16() {
    test_get_os_random_bytes_with_len(16);
}

#[test]
fn get_os_random_bytes_256() {
    test_get_os_random_bytes_with_len(256);
}

#[test]
fn get_os_random_bytes_512() {
    test_get_os_random_bytes_with_len(512);
}

#[test]
fn get_os_random_bytes_1000() {
    test_get_os_random_bytes_with_len(1000);
}

fn test_get_os_random_bytes_with_len(len: u32) {
    let bytes = get_os_random_bytes(len).unwrap();
    assert_eq!(bytes.len(), len as usize);
    assert_ne!(bytes, vec![0u8; len as usize]);
}
