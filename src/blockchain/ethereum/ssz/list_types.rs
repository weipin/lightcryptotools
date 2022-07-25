// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements SSZ type "list" upon `Vec<T>`.

use super::array_types::decode_variable_size_objects_from_bytes;
use super::core::{SszType, BYTES_PER_LENGTH_OFFSET};
use super::decoder::{SszDataDecodingError, SszDecodingItem};
use super::encoder::SszEncodingItem;
use crate::tools::codable::{Decodable, DecodingItem, EncodingItem};

// TODO: implements optimization for `Vec<u8>`

impl<T: SszType> SszType for Vec<T> {
    fn size() -> Option<u32> {
        // Always returns `None`, for a "list" is always variable-size.
        None
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut encoding_item = SszEncodingItem::new();

        if T::size().is_none() {
            for value in self {
                encoding_item.encode_variable_size_data(&value.to_bytes());
            }
        } else {
            for value in self {
                encoding_item.encode_fixed_size_data(&value.to_bytes());
            }
        }

        encoding_item.take_data()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
        match T::size() {
            None => {
                // "...Using the first offset, we can compute the length of the list
                // (divide by BYTES_PER_LENGTH_OFFSET), as it gives us the total number of bytes in
                // the offset data..."
                let decoding_item = SszDecodingItem::new_from_data(&bytes[0..4]).unwrap();
                let payload_offset = u32::decode_from(&decoding_item)?;
                if payload_offset < BYTES_PER_LENGTH_OFFSET
                    || payload_offset % BYTES_PER_LENGTH_OFFSET != 0
                {
                    return Err(SszDataDecodingError::InvalidFormat);
                }
                let headers_len = payload_offset;
                let n = headers_len / BYTES_PER_LENGTH_OFFSET;

                let objects = decode_variable_size_objects_from_bytes(bytes, n, headers_len)?;
                Ok(objects)
            }
            Some(size) => {
                if bytes.len() % (size as usize) != 0 {
                    return Err(SszDataDecodingError::InvalidFormat);
                }
                let n = bytes.len() / (size as usize);
                let mut objects = Vec::with_capacity(n);
                for chunk in bytes.chunks_exact(size as usize) {
                    let decoding_item = SszDecodingItem::new_from_data(chunk).unwrap();
                    let object = T::decode_from(&decoding_item)?;
                    objects.push(object);
                }
                Ok(objects)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::ethereum::ssz::decoder::SszDecodingItem;
    use crate::blockchain::ethereum::ssz::encoder::SszEncodingItem;
    use crate::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
    use crate::tools::codable::{Decodable, DecodingItem, Encodable, EncodingItem};

    /// Tests fixed size element `u8`
    #[test]
    fn test_bytes_encoding() {
        // List[byte, 48](*range(48))
        // List[byte, 0](*range(0))
        // List[byte, 7](*range(7))
        let data = [
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            "",
            "00010203040506",
        ];
        for hex in data {
            let mut encoding_item = SszEncodingItem::new();
            let bytes = hex_to_bytes(hex).unwrap();
            bytes.encode_to(&mut encoding_item);
            assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), hex);
        }
    }

    #[test]
    fn test_bytes_decoding() {
        let data = [
            ("00010203040506", Ok(vec![0_u8, 1, 2, 3, 4, 5, 6])),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
             Ok((0..48).collect())),
            ("", Ok(vec![])),
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(Vec::<u8>::decode_from(&decoding_item), result);
        }
    }

    /// Tests fixed size element `u16`
    #[test]
    fn test_list_of_u16_encoding() {
        // Vector[uint16, 2](uint16(0x4567), uint16(0x0123))
        let mut encoding_item = SszEncodingItem::new();
        let value = vec![0x4567_u16, 0x0123];
        value.encode_to(&mut encoding_item);
        assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), "67452301");
    }

    #[test]
    fn test_list_of_u16_decoding() {
        let data = [("67452301", Ok(vec![0x4567_u16, 0x0123]))];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(Vec::<u16>::decode_from(&decoding_item), result);
        }
    }

    /// Tests fixed size element `[u8; 7]`
    #[test]
    fn test_list_of_byte_array_encoding() {
        // List[Vector[uint8, 7], 3](
        //     [0, 1, 2, 3, 4, 5, 6],
        //     [0, 1, 2, 3, 4, 5, 6],
        //     [0, 1, 2, 3, 4, 5, 6]
        // )
        let mut encoding_item = SszEncodingItem::new();
        let value = vec![
            [0_u8, 1, 2, 3, 4, 5, 6],
            [0_u8, 1, 2, 3, 4, 5, 6],
            [0_u8, 1, 2, 3, 4, 5, 6],
        ];
        value.encode_to(&mut encoding_item);
        assert_eq!(
            bytes_to_lower_hex(&encoding_item.take_data()),
            "000102030405060001020304050600010203040506"
        );
    }

    #[test]
    fn test_list_of_byte_array_decoding() {
        let data = [(
            "000102030405060001020304050600010203040506",
            Ok(vec![
                [0_u8, 1, 2, 3, 4, 5, 6],
                [0_u8, 1, 2, 3, 4, 5, 6],
                [0_u8, 1, 2, 3, 4, 5, 6],
            ]),
        )];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(Vec::<[u8; 7]>::decode_from(&decoding_item), result);
        }
    }

    /// Tests variable size element `&[u8]`
    #[test]
    fn test_array_of_bytes_encoding() {
        // List[List[uint8, 7], 3](
        //     [0, 1, 2, 3, 4, 5, 6],
        //     [0, 1, 2, 3, 4, 5, 6],
        //     [0, 1, 2, 3, 4, 5, 6]
        // )
        let mut encoding_item = SszEncodingItem::new();
        let array = vec![
            vec![0_u8, 1, 2, 3, 4, 5, 6],
            vec![0_u8, 1, 2, 3, 4, 5, 6],
            vec![0_u8, 1, 2, 3, 4, 5, 6],
        ];
        array.encode_to(&mut encoding_item);
        assert_eq!(
            bytes_to_lower_hex(&encoding_item.take_data()),
            "0c000000130000001a000000000102030405060001020304050600010203040506"
        );
    }

    #[test]
    fn test_array_of_bytes_decoding() {
        let data = [(
            "0c000000130000001a000000000102030405060001020304050600010203040506",
            Ok(vec![
                vec![0_u8, 1, 2, 3, 4, 5, 6],
                vec![0_u8, 1, 2, 3, 4, 5, 6],
                vec![0_u8, 1, 2, 3, 4, 5, 6],
            ]),
        )];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(Vec::<Vec<u8>>::decode_from(&decoding_item), result);
        }
    }
}
