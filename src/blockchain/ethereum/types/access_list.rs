// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::blockchain::ethereum::types::{Address, StorageKey};
use std::fmt;
use std::fmt::Display;

pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<StorageKey>,
}

impl Display for AccessListItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}: ", self.address)?;
        writeln!(f, "  [")?;
        for storage_key in &self.storage_keys {
            writeln!(f, "    {},", storage_key)?;
        }
        writeln!(f, "  ]")?;

        Ok(())
    }
}

#[derive(Default)]
pub struct AccessList(pub Vec<AccessListItem>);

impl Display for AccessList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[")?;
        for item in &self.0 {
            writeln!(f, "  {}", item)?;
        }
        write!(f, "]")?;

        Ok(())
    }
}

// impl Display for PayloadEip2930 {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         writeln!(f, "chain_id: {}", self.chain_id)?;
//         writeln!(f, "nonce: {}", self.nonce)?;
//         writeln!(f, "gas_price: {}", self.gas_price)?;
//         writeln!(f, "gas_limit: 0x{:x}", self.gas_limit)?;
//         writeln!(f, "destination: {}", self.destination)?;
//         writeln!(f, "amount: {}", self.amount)?;
//         writeln!(f, "data: 0x{}", bytes_to_lower_hex(&self.data))?;
//         writeln!(f, "access_list: {}", &self.access_list)?;
//
//         Ok(())
//     }
// }
