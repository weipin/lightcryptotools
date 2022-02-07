// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements "errno" for Linux.

use super::LibcErrno;

/// Returns the platform-specific "errno".
pub(crate) fn errno() -> LibcErrno {
    use super::linux::libc;

    unsafe { (*libc::__errno_location()) as LibcErrno }
}
