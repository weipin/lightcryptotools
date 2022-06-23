// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements RLP (Recursive Length Prefix) decoding.
//! https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp

use super::core::RlpItemType;
use super::core::{UintByteLengthOfPayloadByteLength, UintPayloadByteLength};
use std::fmt;
use std::fmt::Display;

/// Decodes a RLP item from `data`.
/// Returns the type and the payload data of the item if the decoding is successful.
pub(crate) fn decode_data(data: &[u8]) -> Result<(RlpItemType, &[u8]), RlpDataDecodingError> {
    let (item_type, header_byte_length, payload_byte_length) = decode_data_header(data)?;
    if data.len() != header_byte_length as usize + payload_byte_length as usize {
        return Err(RlpDataDecodingError::InvalidFormat);
    }

    Ok((item_type, &data[header_byte_length as usize..]))
}

/// Decodes an array of RLP items from `list_payload`.
pub(crate) fn decode_list_payload(
    list_payload: &[u8],
) -> Result<Vec<(RlpItemType, &[u8])>, RlpDataDecodingError> {
    let mut remaining_list_payload = list_payload;
    let mut item_list = Vec::new();
    loop {
        if remaining_list_payload.is_empty() {
            break;
        }

        let (item_type, header_byte_length, payload_byte_length) =
            decode_data_header(remaining_list_payload)?;
        if remaining_list_payload.len()
            < header_byte_length as usize + payload_byte_length as usize
        {
            return Err(RlpDataDecodingError::InvalidFormat);
        }
        let (data1, data2) = remaining_list_payload
            .split_at(header_byte_length as usize + payload_byte_length as usize);
        item_list.push((item_type, &data1[header_byte_length as usize..]));
        remaining_list_payload = data2;
    }

    Ok(item_list)
}

/// Decodes a RLP header from `data`.
///
/// On success, returns
/// - the type of the item (single value or list)
/// - the length of header in bytes
/// - the length of payload (string or list) in bytes
fn decode_data_header(
    data: &[u8],
) -> Result<
    (
        RlpItemType,
        UintByteLengthOfPayloadByteLength,
        UintPayloadByteLength,
    ),
    RlpDataDecodingError,
> {
    if data.is_empty() {
        return Err(RlpDataDecodingError::InvalidFormat);
    }

    let first = *data.first().unwrap();
    match first {
        // "...For a single byte whose value is in the [0x00, 0x7f] range,
        // that byte is its own RLP encoding..."
        0x00..=0x7f => Ok((RlpItemType::SingleValue, 0, 1)),

        // "...if a string is 0-55 bytes long,
        // the RLP encoding consists of a single byte with value 0x80
        // plus the length of the string followed by the string.
        // The range of the first byte is thus [0x80, 0xb7]..."
        0x80..=0xb7 => Ok((
            RlpItemType::SingleValue,
            1,
            (first - 0x80) as UintPayloadByteLength,
        )),

        // "...If a string is more than 55 bytes long,
        // the RLP encoding consists of a single byte with value 0xb7
        // plus the length in bytes of the length of the string in binary form,
        // followed by the length of the string...
        // The range of the first byte is thus [0xb8, 0xbf]..."
        0xb8..=0xbf => {
            let byte_length_of_payload_byte_length = first - 0xb7;
            if data.len() < (1 + byte_length_of_payload_byte_length as usize) {
                return Err(RlpDataDecodingError::InvalidFormat);
            }
            let mut payload_byte_length_bytes =
                [0; std::mem::size_of::<UintPayloadByteLength>()];
            payload_byte_length_bytes[(std::mem::size_of::<UintPayloadByteLength>()
                - byte_length_of_payload_byte_length as usize)..]
                .copy_from_slice(&data[1..=byte_length_of_payload_byte_length as usize]);
            let payload_byte_length =
                UintPayloadByteLength::from_be_bytes(payload_byte_length_bytes) as usize;

            if data.len()
                < (1 + byte_length_of_payload_byte_length as usize + payload_byte_length)
            {
                return Err(RlpDataDecodingError::InvalidFormat);
            }
            Ok((
                RlpItemType::SingleValue,
                1 + byte_length_of_payload_byte_length,
                UintPayloadByteLength::try_from(payload_byte_length).unwrap(),
            ))
        }

        // If the total payload of a list (i.e. the combined length of all its items being RLP encoded)
        // is 0-55 bytes long, the RLP encoding consists of a single byte with value 0xc0
        // plus the length of the list followed by the concatenation of the RLP encodings of the items.
        // The range of the first byte is thus [0xc0, 0xf7]
        0xc0..=0xf7 => Ok((
            RlpItemType::List,
            1,
            (first - 0xc0) as UintPayloadByteLength,
        )),

        // If the total payload of a list is more than 55 bytes long,
        // the RLP encoding consists of a single byte with value 0xf7
        // plus the length in bytes of the length of the payload in binary form,
        // followed by the length of the payload, followed by the concatenation of the RLP encodings of the items.
        // The range of the first byte is thus [0xf8, 0xff].
        0xf8..=0xff => {
            let byte_length_of_payload_byte_length = first - 0xf7;
            if data.len() < (1 + byte_length_of_payload_byte_length as usize) {
                return Err(RlpDataDecodingError::InvalidFormat);
            }
            let mut payload_byte_length_bytes =
                [0; std::mem::size_of::<UintPayloadByteLength>()];
            payload_byte_length_bytes[(std::mem::size_of::<UintPayloadByteLength>()
                - byte_length_of_payload_byte_length as usize)..]
                .copy_from_slice(&data[1..=byte_length_of_payload_byte_length as usize]);
            let payload_byte_length =
                UintPayloadByteLength::from_be_bytes(payload_byte_length_bytes) as usize;

            if data.len()
                < (1 + byte_length_of_payload_byte_length as usize + payload_byte_length)
            {
                return Err(RlpDataDecodingError::InvalidFormat);
            }
            Ok((
                RlpItemType::List,
                1 + byte_length_of_payload_byte_length,
                UintPayloadByteLength::try_from(payload_byte_length).unwrap(),
            ))
        }
    }
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RlpDataDecodingError {
    InvalidFormat,
    TransactionTypeMismatch,
}

impl Display for RlpDataDecodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RlpDataDecodingError::InvalidFormat => {
                write!(f, "Invalid format")
            }
            RlpDataDecodingError::TransactionTypeMismatch => {
                write!(f, "Transaction interpreted with the wrong type")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::quickcheck_macros::quickcheck;

    #[test]
    fn test_examples() {
        // The string “dog” = [ 0x83, ‘d’, ‘o’, ‘g’ ]
        let (item_type, payload) = decode_data(&[0x83, b'd', b'o', b'g']).unwrap();
        assert_eq!(item_type, RlpItemType::SingleValue);
        assert_eq!(payload, "dog".as_bytes());

        // The list [ “cat”, “dog” ] = [ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' ]
        let (item_type, payload) =
            decode_data(&[0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']).unwrap();
        assert_eq!(item_type, RlpItemType::List);
        let items = decode_list_payload(payload).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, RlpItemType::SingleValue);
        assert_eq!(items[0].1, "cat".as_bytes());
        assert_eq!(items[1].0, RlpItemType::SingleValue);
        assert_eq!(items[1].1, "dog".as_bytes());

        // The empty string (‘null’) = [ 0x80 ]
        let (item_type, payload) = decode_data(&[0x80]).unwrap();
        assert_eq!(item_type, RlpItemType::SingleValue);
        assert_eq!(payload, "".as_bytes());

        // The empty list = [ 0xc0 ]
        let (item_type, payload) = decode_data(&[0xc0]).unwrap();
        assert_eq!(item_type, RlpItemType::List);
        assert_eq!(payload, "".as_bytes());

        // The integer 0 = [ 0x80 ]
        //
        // omitted...
        // Same as "The empty string (‘null’)" test above,
        // for the type interpretation relies on applications.

        // The encoded integer 0 (’\x00’) = [ 0x00 ]
        let (item_type, payload) = decode_data(&[0x00]).unwrap();
        assert_eq!(item_type, RlpItemType::SingleValue);
        assert_eq!(payload, &[0]);

        // The encoded integer 15 (’\x0f’) = [ 0x0f ]
        let (item_type, payload) = decode_data(&[0x0f]).unwrap();
        assert_eq!(item_type, RlpItemType::SingleValue);
        assert_eq!(payload, &[0x0f]);

        // The encoded integer 1024 (’\x04\x00’) = [ 0x82, 0x04, 0x00 ]
        let (item_type, payload) = decode_data(&[0x82, 0x04, 0x00]).unwrap();
        assert_eq!(item_type, RlpItemType::SingleValue);
        assert_eq!(u16::from_be_bytes(payload.try_into().unwrap()), 1024);

        // The set theoretical representation of three,
        // [ [], [[]], [ [], [[]] ] ] = [ 0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0 ]
        let (item_type, payload) =
            decode_data(&[0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]).unwrap();
        assert_eq!(item_type, RlpItemType::List);

        let items = decode_list_payload(payload).unwrap();
        let pattern1 = items[0]; // []
        assert_eq!(pattern1.0, RlpItemType::List);
        let sub_items = decode_list_payload(pattern1.1).unwrap();
        assert_eq!(sub_items.len(), 0);

        let pattern2 = items[1]; // [[]]
        assert_eq!(pattern2.0, RlpItemType::List);
        let sub_items = decode_list_payload(pattern2.1).unwrap();
        assert_eq!(sub_items.len(), 1);
        let subsub_items = decode_list_payload(sub_items[0].1).unwrap();
        assert_eq!(subsub_items.len(), 0);

        let pattern3 = items[2]; // [ [], [[]] ]
        assert_eq!(pattern3.0, RlpItemType::List);
        let sub_items = decode_list_payload(pattern3.1).unwrap();
        assert_eq!(sub_items.len(), 2);
        assert_eq!(sub_items[0], pattern1);
        assert_eq!(sub_items[1], pattern2);

        // The string “Lorem ipsum dolor sit amet, consectetur adipisicing elit” =
        // [ 0xb8, 0x38, 'L', 'o', 'r', 'e', 'm', ' ', ... , 'e', 'l', 'i', 't' ]
        let str_bytes = "Lorem ipsum dolor sit amet, consectetur adipisicing elit".as_bytes();
        let mut encoded = vec![0xb8, 0x38];
        encoded.extend(str_bytes);
        let (item_type, payload) = decode_data(&encoded).unwrap();
        assert_eq!(item_type, RlpItemType::SingleValue);
        assert_eq!(payload, str_bytes);
    }

    #[test]
    fn test_decoding_error_cases() {
        // The string “dog” = [ 0x83, ‘d’, ‘o’, ‘g’ ]
        assert!(decode_data(&[0x83, b'd', b'o', b'g', b'f']).is_err()); // data too long
        assert!(decode_data(&[0x83, b'd', b'o']).is_err()); // data too short

        // The set theoretical representation of three,
        // [ [], [[]], [ [], [[]] ] ] = [ 0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0 ]
        let (item_type, payload) =
            decode_data(&[0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]).unwrap();
        assert_eq!(item_type, RlpItemType::List);

        // payload too long
        let mut payload2 = payload.to_vec();
        payload2.extend(&[0x83]);
        assert!(decode_list_payload(&payload2).is_err());

        // payload too short
        let mut payload2 = payload.to_vec();
        payload2.pop();
        assert!(decode_list_payload(&payload2).is_err());
    }

    // Tests that decoding won't panic for whatever data it's fed.
    #[quickcheck]
    fn test_decoding_random_data_will_not_panic(data: Vec<u8>) -> bool {
        let _ = decode_data(&data);
        let _ = decode_list_payload(&data);

        true
    }
}
