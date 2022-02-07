// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::os::{LibcErrno, NtStatus, SecOsStatus};
use std::fmt;
use std::fmt::Display;

/// An error returned by [`get_os_random_bytes`](super::os_random::get_os_random_bytes).
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum GetOsRandomBytesError {
    AppleSecRandom(SecOsStatus),
    LinuxGetRandom(LibcErrno),
    LinuxGetRandomCopiedNumberLessThanRequested,
    WindowsBCryptGenRandom(NtStatus),
}

impl Display for GetOsRandomBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetOsRandomBytesError::AppleSecRandom(status) => {
                write!(f, "SecRandomCopyBytes failed with status {status}")
            }
            GetOsRandomBytesError::LinuxGetRandom(errno) => {
                write!(f, "getrandom failed with errno {errno}")
            }
            GetOsRandomBytesError::LinuxGetRandomCopiedNumberLessThanRequested => {
                write!(
                    f,
                    "getrandom failed: the number of bytes copied is less than the number requested"
                )
            }
            GetOsRandomBytesError::WindowsBCryptGenRandom(status) => {
                write!(f, "BCryptGenRandom failed with status {status}")
            }
        }
    }
}

impl std::error::Error for GetOsRandomBytesError {}
