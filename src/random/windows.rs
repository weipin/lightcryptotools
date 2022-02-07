// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implementation for Windows

use super::error::GetOsRandomBytesError;
use crate::os::windows::bcrypt_gen_random;

/// Returns cryptographically secure random bytes with the specified `len`.
pub(crate) fn get_os_random_bytes_impl(len: u32) -> Result<Vec<u8>, GetOsRandomBytesError> {
    let mut bytes = vec![0u8; len as usize];

    let status = bcrypt_gen_random(&mut bytes);

    // The two highest bits represent Severity.
    // Severity code 0x3 represents error. See [`NtStatus`]
    if status >> 30 == 0x3 {
        Err(GetOsRandomBytesError::WindowsBCryptGenRandom(status))
    } else {
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::get_os_random_bytes_impl;
    use crate::os::windows::bcrypt;
    use crate::os::NtStatus;
    use crate::random::GetOsRandomBytesError;

    #[test]
    fn mock_test_get_os_random_bytes_impl() {
        // success
        {
            let ctx = bcrypt::BCryptGenRandom_context();
            ctx.expect().return_const(0_u32);
            assert_eq!(get_os_random_bytes_impl(16).unwrap(), vec![0u8; 16]);
        }

        // failure
        {
            const STATUS_INVALID_PARAMETER: NtStatus = 0xC000000D;
            let ctx = bcrypt::BCryptGenRandom_context();
            ctx.expect().return_const(STATUS_INVALID_PARAMETER);
            assert_eq!(
                get_os_random_bytes_impl(16).unwrap_err(),
                GetOsRandomBytesError::WindowsBCryptGenRandom(STATUS_INVALID_PARAMETER)
            );
        }
    }
}
