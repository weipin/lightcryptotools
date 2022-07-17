// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::blockchain::ethereum::types::address::Address;
use crate::blockchain::ethereum::types::currency_unit::Wei;
use crate::blockchain::ethereum::types::eoa_nonce::EoaNonce;
use crate::blockchain::ethereum::types::{AccessList, ChainId};
use crate::crypto::ecdsa::SigningError;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransactionBuildingError {
    MissingFields,
    SigningError(SigningError),
}

impl Display for TransactionBuildingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionBuildingError::MissingFields => write!(f, "Some fields are missing"),
            TransactionBuildingError::SigningError(err) => write!(f, "Signing error: {err}"),
        }
    }
}

impl Error for TransactionBuildingError {}

pub struct TransactionBuilder {
    pub(crate) chain_id: Option<ChainId>,
    pub(crate) nonce: Option<EoaNonce>,
    pub(crate) gas_price: Option<Wei>,
    pub(crate) max_priority_fee_per_gas: Option<Wei>,
    pub(crate) max_fee_per_gas: Option<Wei>,
    pub(crate) gas_limit: Option<u64>,
    pub(crate) destination: Option<Address>,
    pub(crate) amount: Option<Wei>,
    pub(crate) data: Option<Vec<u8>>,
    pub(crate) access_list: Option<AccessList>,
}

impl TransactionBuilder {
    pub fn new() -> TransactionBuilder {
        TransactionBuilder {
            chain_id: None,
            nonce: None,
            gas_price: None,
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            gas_limit: None,
            destination: None,
            amount: None,
            data: None,
            access_list: None,
        }
    }

    pub fn with_chain_id(mut self, chain_id: ChainId) -> TransactionBuilder {
        self.chain_id = Some(chain_id);
        self
    }

    pub fn with_nonce(mut self, nonce: EoaNonce) -> TransactionBuilder {
        self.nonce = Some(nonce);
        self
    }

    pub fn with_gas_price(mut self, gas_price: Wei) -> TransactionBuilder {
        self.gas_price = Some(gas_price);
        self
    }

    pub fn with_max_priority_fee_per_gas(
        mut self,
        max_priority_fee_per_gas: Wei,
    ) -> TransactionBuilder {
        self.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
        self
    }

    pub fn with_max_fee_per_gas(mut self, max_fee_per_gas: Wei) -> TransactionBuilder {
        self.max_fee_per_gas = Some(max_fee_per_gas);
        self
    }

    pub fn with_gas_limit(mut self, gas_limit: u64) -> TransactionBuilder {
        self.gas_limit = Some(gas_limit);
        self
    }

    pub fn with_destination(mut self, destination: Address) -> TransactionBuilder {
        self.destination = Some(destination);
        self
    }

    pub fn with_amount(mut self, amount: Wei) -> TransactionBuilder {
        self.amount = Some(amount);
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> TransactionBuilder {
        self.data = Some(data);
        self
    }

    pub fn with_access_list(mut self, access_list: AccessList) -> TransactionBuilder {
        self.access_list = Some(access_list);
        self
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}
