// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implementation for iOS and macOS

use super::error::GetOsRandomBytesError;
use crate::os::apple::sec_random_copy_bytes;

/// Returns cryptographically secure random bytes with the specified `len`.
pub(crate) fn get_os_random_bytes_impl(len: u32) -> Result<Vec<u8>, GetOsRandomBytesError> {
    let mut bytes = vec![0u8; len as usize];

    let ret = sec_random_copy_bytes(&mut bytes);
    if ret == 0 {
        Ok(bytes)
    } else {
        Err(GetOsRandomBytesError::AppleSecRandom(ret))
    }
}

#[cfg(test)]
mod tests {
    use super::get_os_random_bytes_impl;
    use crate::os::apple::security;
    use crate::random::GetOsRandomBytesError;

    #[test]
    fn mock_test_get_os_random_bytes_impl() {
        // success
        {
            let ctx = security::SecRandomCopyBytes_context();
            ctx.expect().return_const(0);
            assert_eq!(get_os_random_bytes_impl(16).unwrap(), vec![0u8; 16]);
        }

        // failure
        {
            let ctx = security::SecRandomCopyBytes_context();
            ctx.expect().return_const(-36);
            assert_eq!(
                get_os_random_bytes_impl(16).unwrap_err(),
                GetOsRandomBytesError::AppleSecRandom(-36)
            );
        }
    }
}
