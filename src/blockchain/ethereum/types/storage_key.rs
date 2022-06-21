// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bigint::bigint_new::ParseIntError;
use crate::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
use std::fmt;
use std::fmt::Display;

pub const STORAGE_KEY_DATA_BYTE_LENGTH: usize = 32;
pub type StorageKeyData = [u8; STORAGE_KEY_DATA_BYTE_LENGTH];

pub struct StorageKey(pub(crate) StorageKeyData);

impl StorageKey {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<StorageKey> {
        if let Ok(data) = bytes.try_into() {
            Some(StorageKey(data))
        } else {
            None
        }
    }

    pub(crate) fn from_hex<T: AsRef<[u8]>>(hex: T) -> Option<StorageKey> {
        if let Ok(bytes) = hex_to_bytes(hex) {
            StorageKey::from_bytes(&bytes)
        } else {
            None
        }
    }
}

impl StorageKey {
    fn to_lower_hex(&self) -> String {
        bytes_to_lower_hex(&self.0)
    }
}

impl Display for StorageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_lower_hex();
        write!(f, "0x{hex}")
    }
}

/// Creates a `StorageKey` from a 64-char hex.
/// The hex must be prefixed with "0x".
///
/// ```text
/// let k: StorageKey = "0x0000000000000000000000000000000000000000000000000000000000000007".try_into().unwrap();
/// ```
impl TryFrom<&str> for StorageKey {
    type Error = ParseIntError;

    fn try_from(value: &str) -> Result<StorageKey, ParseIntError> {
        if let Some(s) = value.strip_prefix("0x") {
            if let Some(address) = StorageKey::from_hex(s) {
                Ok(address)
            } else {
                Err(ParseIntError::InvalidInput)
            }
        } else {
            Err(ParseIntError::InvalidInput)
        }
    }
}
