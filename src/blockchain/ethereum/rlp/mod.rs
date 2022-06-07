// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements RLP (Recursive Length Prefix).
//! https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp

pub(crate) mod core;
pub mod decoder;
pub mod decoding;
pub mod encoder;
pub mod encoding;

pub use self::core::RlpItemType;
