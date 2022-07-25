// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements SSZ type "uintN" upon `u8`, `u16`, `u32`, `u64` and `u128`.
//! Implements SSZ type "boolean" upon `bool`.

use super::core::SszType;
use super::decoder::SszDataDecodingError;

macro_rules! impl_ssztype_for_unsigned_int {
    ($T:ty) => {
        impl SszType for $T {
            fn size() -> Option<u32> {
                Some(std::mem::size_of::<$T>() as u32)
            }

            fn to_bytes(&self) -> Vec<u8> {
                self.to_le_bytes().into()
            }

            fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
                Ok(<$T>::from_le_bytes(bytes.try_into().map_err(|_| SszDataDecodingError::InvalidFormat)?))
            }
        }
    };
}

impl_ssztype_for_unsigned_int!(u8);
impl_ssztype_for_unsigned_int!(u16);
impl_ssztype_for_unsigned_int!(u32);
impl_ssztype_for_unsigned_int!(u64);
impl_ssztype_for_unsigned_int!(u128);

impl SszType for bool {
    fn size() -> Option<u32> {
        Some(std::mem::size_of::<u8>() as u32)
    }

    fn to_bytes(&self) -> Vec<u8> {
        (*self as u8).to_le_bytes().into()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
        let n = u8::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| SszDataDecodingError::InvalidFormat)?,
        );
        match n {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SszDataDecodingError::InvalidFormat),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::ethereum::ssz::decoder::{SszDataDecodingError, SszDecodingItem};
    use crate::blockchain::ethereum::ssz::encoder::SszEncodingItem;
    use crate::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
    use crate::tools::codable::{Decodable, DecodingItem, Encodable, EncodingItem};

    #[test]
    fn test_bool_encoding() {
        // boolean(False)
        // boolean(True)
        let data = [(false, "00"), (true, "01")];
        for (value, hex) in data {
            let mut encoding_item = SszEncodingItem::new();
            value.encode_to(&mut encoding_item);
            assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), hex);
        }
    }

    #[test]
    fn test_bool_decoding() {
        let data = [
            ("00", Ok(false)),
            ("01", Ok(true)),
            ("02", Err(SszDataDecodingError::InvalidFormat)), // invalid value
            ("0001", Err(SszDataDecodingError::InvalidFormat)), // invalid length
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(bool::decode_from(&decoding_item), result);
        }
    }

    #[test]
    fn test_u8_encoding() {
        // uint8(0x0)
        // uint8(0x1)
        // uint8(0xab)
        let data = [(0_u8, "00"), (1, "01"), (0xab, "ab")];
        for (value, hex) in data {
            let mut encoding_item = SszEncodingItem::new();
            value.encode_to(&mut encoding_item);
            assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), hex);
        }
    }

    #[test]
    fn test_u8_decoding() {
        let data = [
            ("00", Ok(0_u8)),
            ("01", Ok(1_u8)),
            ("ab", Ok(0xab_u8)),
            ("0001", Err(SszDataDecodingError::InvalidFormat)), // invalid length
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(u8::decode_from(&decoding_item), result);
        }
    }

    #[test]
    fn test_u16_encoding() {
        // uint16(0x0)
        // uint16(0xabcd)
        let data = [(0_u16, "0000"), (0xabcd, "cdab")];
        for (value, hex) in data {
            let mut encoding_item = SszEncodingItem::new();
            value.encode_to(&mut encoding_item);
            assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), hex);
        }
    }

    #[test]
    fn test_u16_decoding() {
        let data = [
            ("0000", Ok(0_u16)),
            ("cdab", Ok(0xabcd_u16)),
            ("01", Err(SszDataDecodingError::InvalidFormat)), // invalid length
            ("000001", Err(SszDataDecodingError::InvalidFormat)), // invalid length
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(u16::decode_from(&decoding_item), result);
        }
    }

    #[test]
    fn test_u32_encoding() {
        // uint32(0x0)
        // uint32(0x01234567)
        let data = [(0_u32, "00000000"), (0x01234567, "67452301")];
        for (value, hex) in data {
            let mut encoding_item = SszEncodingItem::new();
            value.encode_to(&mut encoding_item);
            assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), hex);
        }
    }

    #[test]
    fn test_u32_decoding() {
        let data = [
            ("00000000", Ok(0_u32)),
            ("67452301", Ok(0x01234567_u32)),
            ("01", Err(SszDataDecodingError::InvalidFormat)), // invalid length
            ("0000000001", Err(SszDataDecodingError::InvalidFormat)), // invalid length
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(u32::decode_from(&decoding_item), result);
        }
    }

    #[test]
    fn test_u64_encoding() {
        let data = [
            // uint64(0x0)
            // uint64(0x0123456789abcdef)
            (0_u64, "0000000000000000"),
            (0x0123456789abcdef, "efcdab8967452301"),
        ];
        for (value, hex) in data {
            let mut encoding_item = SszEncodingItem::new();
            value.encode_to(&mut encoding_item);
            assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), hex);
        }
    }

    #[test]
    fn test_u64_decoding() {
        let data = [
            ("0000000000000000", Ok(0_u64)),
            ("efcdab8967452301", Ok(0x0123456789abcdef_u64)),
            ("01", Err(SszDataDecodingError::InvalidFormat)), // invalid length
            (
                "000000000000000001",
                Err(SszDataDecodingError::InvalidFormat),
            ), // invalid length
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(u64::decode_from(&decoding_item), result);
        }
    }

    #[test]
    fn test_u128_encoding() {
        // uint128(0x0)
        // uint128(0x11223344556677880123456789abcdef)
        let data = [
            (0_u128, "00000000000000000000000000000000"),
            (
                0x11223344556677880123456789abcdef,
                "efcdab89674523018877665544332211",
            ),
        ];
        for (value, hex) in data {
            let mut encoding_item = SszEncodingItem::new();
            value.encode_to(&mut encoding_item);
            assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), hex);
        }
    }

    #[test]
    fn test_u128_decoding() {
        let data = [
            ("00000000000000000000000000000000", Ok(0_u128)),
            (
                "efcdab89674523018877665544332211",
                Ok(0x11223344556677880123456789abcdef_u128),
            ),
            ("01", Err(SszDataDecodingError::InvalidFormat)), // invalid length
            (
                "0000000000000000000000000000000001",
                Err(SszDataDecodingError::InvalidFormat),
            ), // invalid length
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(u128::decode_from(&decoding_item), result);
        }
    }
}
