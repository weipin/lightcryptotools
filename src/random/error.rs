// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::os::apple::SecOsStatus;
use std::fmt;
use std::fmt::Display;

/// An error returned by [`get_os_random_bytes`](super::os_random::get_os_random_bytes).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum GetOsRandomBytesError {
    AppleSecRandom(SecOsStatus),
}

impl Display for GetOsRandomBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetOsRandomBytesError::AppleSecRandom(ret) => {
                write!(f, "SecRandomCopyBytes failed with result {ret}")
            }
        }
    }
}

impl std::error::Error for GetOsRandomBytesError {}
