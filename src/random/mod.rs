// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(target_os = "macos")]
mod apple;

mod error;
mod os_random;

pub use error::GetOsRandomBytesError;
pub use os_random::get_os_random_bytes;