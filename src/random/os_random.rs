// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
#[allow(dead_code)]
pub mod generator_internal {
    use crate::random::GetOsRandomBytesError;

    /// Returns cryptographically secure random bytes with the specified `len`.
    ///
    /// The random bytes is provided by an operating system routine:
    /// - `getrandom(2)` on Linux.
    /// - `SecRandomCopyBytes` on iOS and macOS.
    /// - `BCryptGenRandom` on Windows.
    ///
    /// # Errors
    ///
    /// Will return an error if the underlying system routine fails.
    pub fn get_os_random_bytes(len: u32) -> Result<Vec<u8>, GetOsRandomBytesError> {
        #[cfg(target_os = "macos")]
        use crate::random::apple::get_os_random_bytes_impl;
        #[cfg(target_os = "linux")]
        use crate::random::linux::get_os_random_bytes_impl;
        #[cfg(target_os = "windows")]
        use crate::random::windows::get_os_random_bytes_impl;

        get_os_random_bytes_impl(len)
    }
}

#[cfg(test)]
pub use self::mock_generator_internal as generator;
#[cfg(not(test))]
pub use generator_internal as generator;
