// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements RLP (Recursive Length Prefix) decoding.
//! https://eth.wiki/en/fundamentals/rlp

use crate::blockchain::ethereum::rlp::core::RlpItemType;
use std::fmt;
use std::fmt::Display;

pub fn decode_data(data: &[u8]) -> Result<Vec<(&[u8], RlpItemType)>, RlpDataDecodingError> {
    let mut remaining_data = data;
    let mut item_list = Vec::new();
    loop {
        if remaining_data.is_empty() {
            break;
        }

        let (item_type, header_byte_length, data_byte_length) =
            decode_data_header(remaining_data)?;
        if remaining_data.len() < header_byte_length + data_byte_length {
            return Err(RlpDataDecodingError::InvalidFormat);
        }
        let (data1, data2) = remaining_data.split_at(header_byte_length + data_byte_length);
        item_list.push((&data1[header_byte_length..], item_type));
        remaining_data = data2;
    }

    Ok(item_list)
}

/// Decodes the RLP header of `data`.
///
/// On success, returns
/// - the type of the item (single value or list)
/// - the length of header in bytes
/// - the length of data (string or payload) in bytes
fn decode_data_header(
    data: &[u8],
) -> Result<(RlpItemType, usize, usize), RlpDataDecodingError> {
    if data.is_empty() {
        return Err(RlpDataDecodingError::InvalidFormat);
    }

    let first = *data.first().unwrap() as usize;
    return match first {
        // "...For a single byte whose value is in the [0x00, 0x7f] range,
        // that byte is its own RLP encoding..."
        0x00..=0x7f => Ok((RlpItemType::SingleValue, 0, 1)),

        // "...if a string is 0-55 bytes long,
        // the RLP encoding consists of a single byte with value 0x80
        // plus the length of the string followed by the string.
        // The range of the first byte is thus [0x80, 0xb7]..."
        0x80..=0xb7 => Ok((RlpItemType::SingleValue, 1, first - 0x80)),

        // "...If a string is more than 55 bytes long,
        // the RLP encoding consists of a single byte with value 0xb7
        // plus the length in bytes of the length of the string in binary form,
        // followed by the length of the string...
        // The range of the first byte is thus [0xb8, 0xbf]..."
        0xb8..=0xbf => {
            let byte_length_of_data_byte_length = first - 0xb7;
            if data.len() < (1 + byte_length_of_data_byte_length) {
                return Err(RlpDataDecodingError::InvalidFormat);
            }
            let mut u64_bytes = [0; std::mem::size_of::<u64>()];
            u64_bytes[(std::mem::size_of::<u64>() - byte_length_of_data_byte_length)..]
                .copy_from_slice(&data[1..=byte_length_of_data_byte_length]);
            let data_byte_length = u64::from_be_bytes(u64_bytes) as usize;

            if data.len() < (1 + byte_length_of_data_byte_length + data_byte_length) {
                return Err(RlpDataDecodingError::InvalidFormat);
            }
            Ok((
                RlpItemType::SingleValue,
                1 + byte_length_of_data_byte_length,
                data_byte_length,
            ))
        }

        // If the total payload of a list (i.e. the combined length of all its items being RLP encoded)
        // is 0-55 bytes long, the RLP encoding consists of a single byte with value 0xc0
        // plus the length of the list followed by the concatenation of the RLP encodings of the items.
        // The range of the first byte is thus [0xc0, 0xf7]
        0xc0..=0xf7 => Ok((RlpItemType::List, 1, first - 0xc0)),

        // If the total payload of a list is more than 55 bytes long,
        // the RLP encoding consists of a single byte with value 0xf7
        // plus the length in bytes of the length of the payload in binary form,
        // followed by the length of the payload, followed by the concatenation of the RLP encodings of the items.
        // The range of the first byte is thus [0xf8, 0xff].
        0xf8..=0xff => {
            let byte_length_of_data_byte_length = first - 0xf7;
            if data.len() < (1 + byte_length_of_data_byte_length) {
                return Err(RlpDataDecodingError::InvalidFormat);
            }
            let mut u64_bytes = [0; std::mem::size_of::<u64>()];
            u64_bytes[(std::mem::size_of::<u64>() - byte_length_of_data_byte_length)..]
                .copy_from_slice(&data[1..=byte_length_of_data_byte_length]);
            let data_byte_length = u64::from_be_bytes(u64_bytes) as usize;

            if data.len() < (1 + byte_length_of_data_byte_length + data_byte_length) {
                return Err(RlpDataDecodingError::InvalidFormat);
            }
            Ok((
                RlpItemType::List,
                1 + byte_length_of_data_byte_length,
                data_byte_length as usize,
            ))
        }

        _ => {
            panic!("")
        }
    };
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RlpDataDecodingError {
    InvalidFormat,
}

impl Display for RlpDataDecodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RlpDataDecodingError::InvalidFormat => {
                write!(f, "Invalid format")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_examples() {
        // The string “dog” = [ 0x83, ‘d’, ‘o’, ‘g’ ]
        let items = decode_data(&[0x83, b'd', b'o', b'g']).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, "dog".as_bytes());
        assert_eq!(items[0].1, RlpItemType::SingleValue);

        // The list [ “cat”, “dog” ] = [ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' ]
        let items =
            decode_data(&[0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, RlpItemType::List);
        let items = decode_data(items[0].0).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, "cat".as_bytes());
        assert_eq!(items[0].1, RlpItemType::SingleValue);
        assert_eq!(items[1].0, "dog".as_bytes());
        assert_eq!(items[1].1, RlpItemType::SingleValue);

        // The empty string (‘null’) = [ 0x80 ]
        let items = decode_data(&[0x80]).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, "".as_bytes());
        assert_eq!(items[0].1, RlpItemType::SingleValue);

        // The empty list = [ 0xc0 ]
        let items = decode_data(&[0xc0]).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, "".as_bytes());
        assert_eq!(items[0].1, RlpItemType::List);

        // The integer 0 = [ 0x80 ]
        //
        // omitted...
        // Same as "The empty string (‘null’)" test above,
        // for the type interpretation relies on the application.

        // The encoded integer 0 (’\x00’) = [ 0x00 ]
        let items = decode_data(&[0x00]).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, &[0]);
        assert_eq!(items[0].1, RlpItemType::SingleValue);

        // The encoded integer 15 (’\x0f’) = [ 0x0f ]
        let items = decode_data(&[0x0f]).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, &[0x0f]);
        assert_eq!(items[0].1, RlpItemType::SingleValue);

        // The encoded integer 1024 (’\x04\x00’) = [ 0x82, 0x04, 0x00 ]
        let items = decode_data(&[0x82, 0x04, 0x00]).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(u16::from_be_bytes(items[0].0.try_into().unwrap()), 1024);
        assert_eq!(items[0].1, RlpItemType::SingleValue);

        // The set theoretical representation of three,
        // [ [], [[]], [ [], [[]] ] ] = [ 0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0 ]
        let items = decode_data(&[0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]).unwrap();
        assert_eq!(items[0].1, RlpItemType::List);
        let items = decode_data(items[0].0).unwrap();
        assert_eq!(items.len(), 3);

        let pattern1 = items[0]; // []
        assert_eq!(pattern1.1, RlpItemType::List);
        let sub_items = decode_data(pattern1.0).unwrap();
        assert_eq!(sub_items.len(), 0);

        let pattern2 = items[1]; // [[]]
        assert_eq!(pattern2.1, RlpItemType::List);
        let sub_items = decode_data(pattern2.0).unwrap();
        assert_eq!(sub_items.len(), 1);
        let subsub_items = decode_data(sub_items[0].0).unwrap();
        assert_eq!(subsub_items.len(), 0);

        let pattern3 = items[2]; // [ [], [[]] ]
        assert_eq!(pattern3.1, RlpItemType::List);
        let sub_items = decode_data(pattern3.0).unwrap();
        assert_eq!(sub_items.len(), 2);
        assert_eq!(sub_items[0], pattern1);
        assert_eq!(sub_items[1], pattern2);

        // The string “Lorem ipsum dolor sit amet, consectetur adipisicing elit” =
        // [ 0xb8, 0x38, 'L', 'o', 'r', 'e', 'm', ' ', ... , 'e', 'l', 'i', 't' ]
        let str_bytes = "Lorem ipsum dolor sit amet, consectetur adipisicing elit".as_bytes();
        let mut encoded = vec![0xb8, 0x38];
        encoded.extend(str_bytes);
        let items = decode_data(&encoded).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, str_bytes);
        assert_eq!(items[0].1, RlpItemType::SingleValue);
    }
}
