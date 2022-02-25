// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements system-call wrappers for Windows.

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
#[allow(dead_code)]
pub(crate) mod bcrypt_internal {
    use crate::os::NtStatus;
    use std::ffi::c_void;

    #[link(name = "bcrypt")]
    extern "system" {
        // NTSTATUS BCryptGenRandom(
        // [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
        // [in, out] PUCHAR            pbBuffer,
        // [in]      ULONG             cbBuffer,
        // [in]      ULONG             dwFlags
        // );
        //
        // PUCHAR: a pointer to a UCHAR, which is `unsigned char`.
        // ULONG: 32-bit unsigned integer.
        #[allow(non_snake_case)]
        pub(crate) fn BCryptGenRandom(
            hAlgorithm: *mut c_void,
            pBuffer: *mut u8,
            cbBuffer: u32,
            dwFlags: u32,
        ) -> NtStatus;
    }
}

#[cfg(test)]
pub(crate) use self::mock_bcrypt_internal as bcrypt;
use crate::os::NtStatus;
#[cfg(not(test))]
pub(crate) use bcrypt_internal as bcrypt;

/// Fills `dest` with random bytes.
///
/// Returns a [`NtStatus`] that indicates the success or failure of the function.
pub(crate) fn bcrypt_gen_random(dest: &mut [u8]) -> NtStatus {
    use std::ptr::null_mut;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;
    // The parameter `hAlgorithm` must be NULL,
    // if the system-preferred random number generator algorithm (`BCRYPT_USE_SYSTEM_PREFERRED_RNG`) is used,
    unsafe {
        bcrypt::BCryptGenRandom(
            null_mut(),
            dest.as_mut_ptr(),
            dest.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    }
}
