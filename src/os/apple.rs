// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements system-call wrappers for both iOS and macOS.

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
#[allow(dead_code)]
pub(crate) mod security_internal {
    use crate::os::SecOsStatus;
    use std::ffi::c_void;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        // Function [`SecRandomCopyBytes`][1]
        // `int SecRandomCopyBytes(SecRandomRef rnd, size_t count, void *bytes);`
        //
        // [1]: https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc
        #[allow(non_snake_case)]
        pub(crate) fn SecRandomCopyBytes(
            rnd: *const c_void,
            count: usize,
            bytes: *mut u8,
        ) -> SecOsStatus;
    }
}

#[cfg(test)]
pub(crate) use self::mock_security_internal as security;
use crate::os::SecOsStatus;
#[cfg(not(test))]
pub(crate) use security_internal as security;

/// Fills `dest` with random bytes.
///
/// Returns 0 on success, or some other value on failure. See [`SecOsStatus`].
pub(crate) fn sec_random_copy_bytes(dest: &mut [u8]) -> SecOsStatus {
    use std::ptr::null;

    // Uses the default random number generator `kSecRandomDefault`,
    // which ["is a synonym for NULL"][1]
    //
    // [1]: https://developer.apple.com/documentation/security/ksecrandomdefault?language=objc
    unsafe { security::SecRandomCopyBytes(null(), dest.len(), dest.as_mut_ptr()) }
}
