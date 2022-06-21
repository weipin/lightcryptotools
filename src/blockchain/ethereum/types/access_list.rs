// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::blockchain::ethereum::types::{Address, StorageKey};

pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<StorageKey>,
}

#[derive(Default)]
pub struct AccessList(pub Vec<AccessListItem>);
