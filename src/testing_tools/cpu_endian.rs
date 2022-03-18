// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub(crate) fn cpu_endian() -> String {
    // Adapted from rust-cpu-endian:
    // https://github.com/wbcchsyn/rust-cpu-endian/blob/master/src/lib.rs
    let v: u16 = 0x00ff;
    let first_octet: u8 = unsafe {
        let ptr = &v as *const u16 as *const u8;
        *ptr
    };

    // If the byte-order is little-endian, the first octet should be 0xff, or if big-endian,
    // it should be 0x00.
    if first_octet == 0xff {
        "little-endian".to_string()
    } else {
        "big-endian".to_string()
    }
}
