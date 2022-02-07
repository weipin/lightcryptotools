// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::os::raw::c_int;

/// Type represents [`OsStatus`][1] from Apple Security projects.
///
/// [1]: https://github.com/apple-oss-distributions/Security/blob/Security-59754.140.13/base/SecBase.h#L323
pub type SecOsStatus = c_int;

/// Type represents "errno" of libc.
pub type LibcErrno = c_int;

/// Type represents [`NTSTATUS`][1] (Windows Error Code).
///
/// [1]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
pub type NtStatus = u32;

#[cfg(target_os = "macos")]
pub(crate) mod apple;
#[cfg(target_os = "linux")]
pub(crate) mod errno;
#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "windows")]
pub(crate) mod windows;
