// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RlpItemType {
    SingleValue,
    List,
}

// For data with size more than 55 bytes long,
// "...The range of the first byte is thus [0xb8, 0xbf]..." for single value, and
// "...The range of the first byte is thus [0xf8, 0xff]..." for list.
//
// In either case, the max "length in bytes of the length" is 8.
pub(crate) const MAX_BYTE_LENGTH_OF_DATA_BYTE_LENGTH: usize = 8;
