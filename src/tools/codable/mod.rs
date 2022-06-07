// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Traits for encoding (serializing) and decoding (deserializing) Rust data structures.
//!
//! TODO: These traits are designed explicitly for RLP and are overly simplified and unstable.

mod core;
mod decodable;
mod encodable;

pub use self::core::decode;
pub use self::core::encode;

pub use decodable::*;
pub use encodable::*;
