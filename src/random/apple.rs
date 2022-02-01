// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implementation for iOS and macOS

use super::error::GetOsRandomBytesError;
use crate::os::apple::sec_random_copy_bytes;

pub(crate) fn get_os_random_bytes_imp(len: usize) -> Result<Vec<u8>, GetOsRandomBytesError> {
    let mut bytes = vec![0u8; len];

    let ret = sec_random_copy_bytes(&mut bytes);
    if ret == 0 {
        Ok(bytes)
    } else {
        Err(GetOsRandomBytesError::AppleSecRandom(ret))
    }
}
