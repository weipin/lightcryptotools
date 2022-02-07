// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements system-call wrappers for Linux.

use super::errno::errno;
use super::LibcErrno;

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
#[allow(dead_code)]
pub(crate) mod libc_internal {
    use std::os::raw::{c_int, c_uint};

    extern "C" {
        // int * __errno_location(void);
        pub(crate) fn __errno_location() -> *mut c_int;

        // ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
        pub(crate) fn getrandom(buffer: *mut u8, length: usize, flag: c_uint) -> isize;
    }
}

#[cfg(test)]
pub(crate) use self::mock_libc_internal as libc;
#[cfg(not(test))]
pub(crate) use libc_internal as libc;

/// Fills `dest` with random bytes.
///
/// Returns the number of bytes that were copied to `dest`.
///
/// # Errors
///
/// Will return a LibcErrno on failure.
pub(crate) fn getrandom(dest: &mut [u8]) -> Result<isize, LibcErrno> {
    // For the argument `flag`, 0 is passed.
    // The default behavior is the one expected:
    // - Draws entropy from the urandom source.
    // - Will block if the urandom source hasn't been initialized.
    //
    // References:
    // - [Myths about /dev/urandom][1]
    // - [PEP 524][2]
    //
    // [1]: https://www.2uo.de/myths-about-urandom/
    // [2]: https://www.python.org/dev/peps/pep-0524/
    let ret = unsafe { libc::getrandom(dest.as_mut_ptr(), dest.len(), 0) };
    if ret == -1 {
        Err(errno())
    } else {
        Ok(ret)
    }
}
