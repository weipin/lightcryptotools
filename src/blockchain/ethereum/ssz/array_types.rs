// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements SSZ type "vector" upon `[T; N]`.

use super::core::SszType;
use super::core::BYTES_PER_LENGTH_OFFSET;
use super::decoder::{SszDataDecodingError, SszDecodingItem};
use super::encoder::SszEncodingItem;
use crate::tools::codable::{Decodable, DecodingItem, EncodingItem};
use std::fmt::Debug;

// TODO: implements optimization for `[u8; N]`

impl<T: SszType + Debug, const N: usize> SszType for [T; N] {
    #[rustfmt::skip]
    fn size() -> Option<u32> {
        // Determined by whether or not the element type is fixed-size:
        // - Returns `element_size * N` for fixed-size.
        // - Returns `None` for variable-size.
        T::size().map(|element_size| element_size.checked_mul(
            u32::try_from(N).unwrap()
        ).unwrap())
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
                let n = u32::try_from(N).unwrap();
                let headers_len = n.checked_mul(BYTES_PER_LENGTH_OFFSET).unwrap();

                let objects = decode_variable_size_objects_from_bytes(bytes, n, headers_len)?;
                Ok(objects.try_into().unwrap())
            }
            Some(size) => {
                let n = u32::try_from(N).unwrap();
                if bytes.len() != size.checked_mul(n).unwrap() as usize {
                    return Err(SszDataDecodingError::InvalidFormat);
                }
                let mut objects = Vec::with_capacity(N);
                for chunk in bytes.chunks_exact(size as usize) {
                    let decoding_item = SszDecodingItem::new_from_data(chunk).unwrap();
                    let object = T::decode_from(&decoding_item)?;
                    objects.push(object);
                }
                Ok(objects.try_into().unwrap())
            }
        }
    }
}

/// Decodes `T`s from `bytes`. `T` must be variable-size.
///
/// # Parameters
///
/// * `objects_number`: the number of `T`s encoded in `bytes`.
/// * `headers_len`: the length of "headers" in bytes.
pub(crate) fn decode_variable_size_objects_from_bytes<T: SszType>(
    bytes: &[u8],
    objects_number: u32,
    headers_len: u32,
) -> Result<Vec<T>, SszDataDecodingError> {
    debug_assert!(T::size().is_none());
    debug_assert_eq!(
        objects_number.checked_mul(BYTES_PER_LENGTH_OFFSET).unwrap(),
        headers_len
    );

    let bytes_len =
        u32::try_from(bytes.len()).map_err(|_| SszDataDecodingError::InvalidFormat)?;
    if bytes_len < headers_len {
        return Err(SszDataDecodingError::InvalidFormat);
    }

    // Creates an array of offsets,
    // for "...The size of each object in the vector/list can be inferred from the difference of two offsets...".
    //
    // A "sentinel" offset (`bytes_len`) is appended at the end,
    // so the byte length of the last object can be calculated normally as the rest.
    let mut offsets = Vec::with_capacity((objects_number + 1) as usize); // +1 for the sentinel offset
    let mut previous_offset = 0;
    for chunk in bytes[0..(headers_len as usize)].chunks_exact(BYTES_PER_LENGTH_OFFSET as usize)
    {
        let decoding_item = SszDecodingItem::new_from_data(chunk).unwrap();
        let offset = u32::decode_from(&decoding_item)?;
        if offset < previous_offset || offset > bytes_len {
            return Err(SszDataDecodingError::InvalidFormat);
        }
        offsets.push(offset);
        previous_offset = offset;
    }
    // Appends the sentinel offset.
    if !offsets.is_empty() {
        offsets.push(bytes_len);
    }

    // Iterates `offsets` over all contiguous and overlapping windows of length 2,
    // and creates the objects.
    let mut objects = Vec::with_capacity(objects_number as usize);
    for w in offsets.windows(2) {
        let offset1 = w[0];
        let offset2 = w[1];
        debug_assert!(offset2 >= offset1);
        let decoding_item =
            SszDecodingItem::new_from_data(&bytes[(offset1 as usize)..(offset2 as usize)])
                .unwrap();
        let object = T::decode_from(&decoding_item)?;
        objects.push(object);
    }

    Ok(objects)
}

#[cfg(test)]
mod tests {
    use crate::blockchain::ethereum::ssz::decoder::{SszDataDecodingError, SszDecodingItem};
    use crate::blockchain::ethereum::ssz::encoder::SszEncodingItem;
    use crate::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
    use crate::tools::codable::{Decodable, DecodingItem, Encodable, EncodingItem};

    /// Tests fixed size element `u8`
    #[test]
    fn test_byte_array_encoding() {
        // Vector[uint8, 7](uint8(0x0), uint8(0x1), uint8(0x2), uint8(0x3), uint8(0x4), uint8(0x5), uint8(0x6));
        let mut encoding_item = SszEncodingItem::new();
        let value = [0_u8, 1, 2, 3, 4, 5, 6];
        value.encode_to(&mut encoding_item);
        assert_eq!(
            bytes_to_lower_hex(&encoding_item.take_data()),
            "00010203040506"
        );
    }

    #[test]
    fn test_byte_array_decoding() {
        let data = [
            ("00010203040506", Ok([0_u8, 1, 2, 3, 4, 5, 6])),
            ("0000010203040506", Err(SszDataDecodingError::InvalidFormat)), // invalid length
            ("00", Err(SszDataDecodingError::InvalidFormat)),
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(<[u8; 7]>::decode_from(&decoding_item), result);
        }
    }

    /// Tests fixed size element `[u8, 7]`
    #[test]
    fn test_array_of_byte_array_encoding() {
        // Vector[Vector[uint8, 7], 3](
        //     [0, 1, 2, 3, 4, 5, 6],
        //     [0, 1, 2, 3, 4, 5, 6],
        //     [0, 1, 2, 3, 4, 5, 6]
        // )
        let mut encoding_item = SszEncodingItem::new();
        let value = [
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
    fn test_array_of_byte_array_decoding() {
        let data = [
            (
                "000102030405060001020304050600010203040506",
                Ok([
                    [0_u8, 1, 2, 3, 4, 5, 6],
                    [0_u8, 1, 2, 3, 4, 5, 6],
                    [0_u8, 1, 2, 3, 4, 5, 6],
                ]),
            ),
            ("0001020304050600", Err(SszDataDecodingError::InvalidFormat)), // invalid length
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(<[[u8; 7]; 3]>::decode_from(&decoding_item), result);
        }
    }

    /// Tests variable size element `Vec<u8>`
    #[test]
    fn test_array_of_bytes_encoding() {
        // Vector[List[uint8, 7], 3](
        //     [0, 1, 2, 3, 4, 5, 6],
        //     [0, 1, 2, 3, 4, 5, 6],
        //     [0, 1, 2, 3, 4, 5, 6]
        // )
        let mut encoding_item = SszEncodingItem::new();
        let value = [
            vec![0_u8, 1, 2, 3, 4, 5, 6],
            vec![0_u8, 1, 2, 3, 4, 5, 6],
            vec![0_u8, 1, 2, 3, 4, 5, 6],
        ];
        value.encode_to(&mut encoding_item);
        assert_eq!(
            bytes_to_lower_hex(&encoding_item.take_data()),
            "0c000000130000001a000000000102030405060001020304050600010203040506"
        );
    }

    #[test]
    fn test_array_of_bytes_decoding() {
        let data = [
            (
                "0c000000130000001a000000000102030405060001020304050600010203040506",
                Ok([
                    vec![0_u8, 1, 2, 3, 4, 5, 6],
                    vec![0_u8, 1, 2, 3, 4, 5, 6],
                    vec![0_u8, 1, 2, 3, 4, 5, 6],
                ]),
            ),
            ("0c0000", Err(SszDataDecodingError::InvalidFormat)), // invalid length
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(<[Vec<u8>; 3]>::decode_from(&decoding_item), result);
        }
    }
}
