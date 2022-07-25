// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Partially implements Simple Serialize (SSZ):
//! - https://github.com/ethereum/consensus-specs/blob/v1.1.1/ssz/simple-serialize.md
//! - https://eth2book.info/altair/part2/building_blocks/ssz
//!
//! Uses Python package "remerkleable" for the generation of testing data:
//! https://github.com/protolambda/remerkleable
//!
//! TODO: types, derive and merkleization

mod array_types;
mod basic_types;
mod container_types;
mod core;
mod decoder;
mod encoder;
mod list_types;

pub use self::core::SszType;
pub use decoder::{SszDataDecodingError, SszDecodingItem};
pub use encoder::SszEncodingItem;
