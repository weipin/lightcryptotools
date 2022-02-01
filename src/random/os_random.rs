// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::error::GetOsRandomBytesError;

/// Gets cryptographically secure random bytes with the specified `len`.
///
/// The random bytes is provided by an operating system routine:
/// - `getrandom(2)` on Linux.
/// - `SecRandomCopyBytes` on iOS and macOS.
/// - `BCryptGenRandom` on Windows.
///
/// # Errors
///
/// Will return Err if the underlying system routine fails.
pub fn get_os_random_bytes(len: usize) -> Result<Vec<u8>, GetOsRandomBytesError> {
    #[cfg(target_os = "macos")]
    use super::apple::get_os_random_bytes_imp;

    get_os_random_bytes_imp(len)
}
