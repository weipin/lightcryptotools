// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements system-call wrappers for both iOS and macOS.
use std::os::raw::c_int;

/// Type represents [`OsStatus`][1] from Apple Security projects
///
/// [1]: https://github.com/apple-oss-distributions/Security/blob/Security-59754.140.13/base/SecBase.h#L323
pub type SecOsStatus = c_int;

mod framework {
    use super::SecOsStatus;
    use std::ffi::c_void;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        // Function [`SecRandomCopyBytes`][1]
        // `int SecRandomCopyBytes(SecRandomRef rnd, size_t count, void *bytes);`
        //
        // [1]: https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc
        pub(super) fn SecRandomCopyBytes(
            rnd: *const c_void,
            count: usize,
            bytes: *mut u8,
        ) -> SecOsStatus;
    }
}

/// Fills `dest` with random bytes.
///
/// Returns 0 on success, or some other value on failure. See [`SecOsStatus`].
pub(crate) fn sec_random_copy_bytes(dest: &mut [u8]) -> SecOsStatus {
    use std::ptr::null;

    // Uses the default random number generator `kSecRandomDefault`,
    // which ["is a synonym for NULL"][1]
    //
    // [1]: https://developer.apple.com/documentation/security/ksecrandomdefault?language=objc
    unsafe { framework::SecRandomCopyBytes(null(), dest.len(), dest.as_mut_ptr()) }
}
