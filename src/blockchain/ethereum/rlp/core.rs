// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Common definitions for RLP.

/// Represents RLP item types.
///
/// "...
/// The RLP encoding function takes in an item.
/// An item is defined as follows：
///
/// - a string (i.e. byte array) is an item
/// - a list of items is an item
/// ..."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlpItemType {
    SingleValue,
    List,
}

// For encoding data with size more than 55 bytes long,
// "...The range of the first byte is thus [0xb8, 0xbf]..." for single value, and
// "...The range of the first byte is thus [0xf8, 0xff]..." for list.
//
// In either case, the maximum of "length in bytes of the length" is 8.
pub(crate) const MAX_BYTE_LENGTH_OF_PAYLOAD_BYTE_LENGTH: usize = 8;

pub(crate) type UintByteLengthOfPayloadByteLength = u8;
pub(crate) type UintPayloadByteLength = u64;
