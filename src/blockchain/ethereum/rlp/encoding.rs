// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements RLP (Recursive Length Prefix) encoding.
//! https://eth.wiki/en/fundamentals/rlp

use crate::blockchain::ethereum::rlp::core::{
    RlpItemType, MAX_BYTE_LENGTH_OF_DATA_BYTE_LENGTH,
};
use crate::tools::bytes::strip_leading_zeros;

pub fn encode_single_value(data: &[u8]) -> Vec<u8> {
    encode_item(data, RlpItemType::SingleValue)
}

pub fn encode_list(data: &[u8]) -> Vec<u8> {
    encode_item(data, RlpItemType::List)
}

pub fn encode_item(data: &[u8], item_type: RlpItemType) -> Vec<u8> {
    let mut header = encode_data_length(data, item_type);
    let mut encoded = Vec::with_capacity(header.len() + data.len());
    encoded.append(&mut header);
    encoded.extend(data);

    encoded
}

/// a convenient function
pub fn encode_and_concat_items(items: &[(&[u8], RlpItemType)]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for &(data, item_type) in items {
        encoded.append(&mut encode_item(data, item_type));
    }

    encoded
}

/// Returns RLP header of `data`.
///
/// `data`: the string/payload in its binary form.
/// While this function encodes only the length, the data itself is required to check the first byte.
fn encode_data_length(data: &[u8], item_type: RlpItemType) -> Vec<u8> {
    let data_length = data.len();

    if item_type == RlpItemType::SingleValue
        && data_length == 1
        && *data.first().unwrap() < 0x80
    {
        // "For a single byte whose value is in the [0x00, 0x7f] range, that byte is its own RLP encoding."
        return vec![];
    }

    return if data_length < 56 {
        match item_type {
            // "...if a string is 0-55 bytes long,
            // the RLP encoding consists of a single byte with value 0x80
            // plus the length of the string..."
            RlpItemType::SingleValue => {
                vec![0x80 + data_length as u8]
            }

            // "...if the total payload of a list is 0-55 bytes long,
            // the RLP encoding consists of a single byte with value 0xc0
            // plus the length of the list..."
            RlpItemType::List => {
                vec![0xc0 + data_length as u8]
            }
        }
    } else {
        let base_value = match item_type {
            // "...If a string is more than 55 bytes long,
            // the RLP encoding consists of a single byte with value 0xb7..."
            RlpItemType::SingleValue => 0xb7,

            // "...If the total payload of a list is more than 55 bytes long,
            // the RLP encoding consists of a single byte with value 0xf7..."
            RlpItemType::List => 0xf7,
        };

        // Represents `data_length` in bytes, big-endian without leading zero bytes
        let bytes = data_length.to_be_bytes();
        let data_length_bytes = strip_leading_zeros(&bytes);
        if data_length_bytes.len() > MAX_BYTE_LENGTH_OF_DATA_BYTE_LENGTH {
            // this should never happen, for usize is 8 bytes on a 64 bit target
            panic!("RLP encoding data too large!");
        }

        let mut header = Vec::with_capacity(1 + data_length_bytes.len());
        // "...plus the length in bytes of the length of the string/payload in binary form..."
        header.push(base_value + data_length_bytes.len() as u8);
        // "...followed by the length of the string/payload..."
        header.extend(data_length_bytes);

        header
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_examples() {
        // The string “dog” = [ 0x83, ‘d’, ‘o’, ‘g’ ]
        assert_eq!(
            encode_single_value("dog".as_bytes()),
            vec![0x83, b'd', b'o', b'g']
        );

        // The list [ “cat”, “dog” ] = [ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' ]
        let items = [
            (&[b'c', b'a', b't'][..], RlpItemType::SingleValue),
            (&[b'd', b'o', b'g'][..], RlpItemType::SingleValue),
        ];
        let encoded_payload = encode_and_concat_items(&items);
        assert_eq!(
            encode_list(&encoded_payload),
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );

        // The empty string (‘null’) = [ 0x80 ]
        assert_eq!(encode_single_value(&[]), vec![0x80]);

        // The empty list = [ 0xc0 ]
        assert_eq!(encode_list(&[]), vec![0xc0]);

        // The integer 0 = [ 0x80 ]
        assert_eq!(
            encode_single_value(strip_leading_zeros(&0_u8.to_be_bytes())),
            vec![0x80]
        );

        // The encoded integer 0 (’\x00’) = [ 0x00 ]
        assert_eq!(encode_single_value(&[0x00]), vec![0x00]);

        // The encoded integer 15 (’\x0f’) = [ 0x0f ]
        assert_eq!(encode_single_value(&[0x0f]), vec![0x0f]);

        // The encoded integer 1024 (’\x04\x00’) = [ 0x82, 0x04, 0x00 ]
        assert_eq!(
            encode_single_value(strip_leading_zeros(&1024_usize.to_be_bytes())),
            vec![0x82, 0x04, 0x00]
        );

        // The set theoretical representation of three,
        // [ [], [[]], [ [], [[]] ] ] = [ 0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0 ]
        let encoded1 = encode_list(&[]); // []
        let encoded2 = encode_list(&encoded1); // [[]]
        let mut payload = encoded1.clone();
        payload.extend(encoded2.clone()); // [], [[]]
        let encoded3 = encode_list(&payload); // [ [], [[]] ]
        let mut payload = encoded1.clone();
        payload.extend(&encoded2);
        payload.extend(&encoded3);
        assert_eq!(
            encode_list(&payload),
            vec![0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]
        );

        // The string
        // “Lorem ipsum dolor sit amet, consectetur adipisicing elit” =
        // [ 0xb8, 0x38, 'L', 'o', 'r', 'e', 'm', ' ', ... , 'e', 'l', 'i', 't' ]
        let str_bytes = "Lorem ipsum dolor sit amet, consectetur adipisicing elit".as_bytes();
        let mut encoded = vec![0xb8, 0x38];
        encoded.extend(str_bytes);
        assert_eq!(encode_single_value(str_bytes), encoded);
    }
}
