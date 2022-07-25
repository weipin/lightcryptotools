// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements SSZ type "container" upon Rust structs.

use super::core::SszType;
use super::core::BYTES_PER_LENGTH_OFFSET;
use super::decoder::{SszDataDecodingError, SszDecodingItem};
use super::encoder::SszEncodingItem;
use crate::tools::codable::{Decodable, DecodingItem};

impl SszEncodingItem {
    /// Encodes `object` as a container element.
    pub fn encode_as_container_element<T: SszType>(&mut self, object: &T) {
        if T::size().is_none() {
            self.encode_variable_size_data(&object.to_bytes());
        } else {
            self.encode_fixed_size_data(&object.to_bytes());
        }
    }
}

impl<'a> SszDecodingItem<'a> {
    /// Decodes `self` into a vector of `SszDecodingItem`,
    /// each corresponds to a container element.
    ///
    /// # Parameters
    ///
    /// * `sizes`: the "sizes" of the container elements, in the same order the serialization takes place.
    pub fn decode_as_items(
        &self,
        sizes: &[Option<u32>],
    ) -> Result<Vec<Self>, SszDataDecodingError> {
        // Calculates the "headers length" in bytes
        let mut headers_len = 0;
        for &size in sizes {
            match size {
                None => {
                    headers_len += BYTES_PER_LENGTH_OFFSET;
                }
                Some(size) => {
                    headers_len += size;
                }
            }
        }
        let bytes_len =
            u32::try_from(self.data.len()).map_err(|_| SszDataDecodingError::InvalidFormat)?;
        if bytes_len < headers_len {
            return Err(SszDataDecodingError::InvalidFormat);
        }

        let mut items = Vec::with_capacity(sizes.len());

        // Creates `SszDecodingItem` backwards --
        // first creates and pushes the `SszDecodingItem` of the last element and works towards the first.
        //
        // This approach is to handle the situation that we need two offsets, the current one and the next one,
        // to infer the size of an element size. The next one wouldn't be available if we instead iterate forwards.

        // The offset of the last iteration.
        // Sets to `bytes_len` for the first iteration (the last container element).
        let mut previous_offset_rev = bytes_len;

        // The header "starting point" of the previously iterated container item.
        // From the elements' "natural order" perspective, this is the header starting point of
        // the "next" container item.
        let mut header_cursor_rev = headers_len;
        for &size in sizes.iter().rev() {
            match size {
                None => {
                    // Variable-size element.
                    let decoding_item = SszDecodingItem::new_from_data(
                        &self.data[(header_cursor_rev - BYTES_PER_LENGTH_OFFSET) as usize
                            ..(header_cursor_rev as usize)],
                    )
                    .unwrap();
                    let offset = u32::decode_from(&decoding_item)?;
                    if offset > previous_offset_rev {
                        return Err(SszDataDecodingError::InvalidFormat);
                    }
                    let decoding_item = SszDecodingItem::new_from_data(
                        &self.data[(offset as usize)..(previous_offset_rev as usize)],
                    )
                    .unwrap();
                    items.push(decoding_item);

                    header_cursor_rev -= BYTES_PER_LENGTH_OFFSET;
                    previous_offset_rev = offset;
                }
                Some(size) => {
                    // Fixed-size element.
                    if size > header_cursor_rev {
                        return Err(SszDataDecodingError::InvalidFormat);
                    }
                    let decoding_item = SszDecodingItem::new_from_data(
                        &self.data
                            [(header_cursor_rev - size) as usize..(header_cursor_rev as usize)],
                    )
                    .unwrap();
                    items.push(decoding_item);
                    header_cursor_rev -= size;
                }
            }
        }

        items.reverse();
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::ethereum::ssz::core::SszType;
    use crate::blockchain::ethereum::ssz::decoder::{SszDataDecodingError, SszDecodingItem};
    use crate::blockchain::ethereum::ssz::encoder::SszEncodingItem;
    use crate::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
    use crate::tools::codable::{Decodable, DecodingItem, Encodable, EncodingItem};

    #[test]
    fn test_small_test_struct_encoding() {
        // class SmallTestStruct(Container):
        //     A: uint16
        //     B: uint16
        //
        // SmallTestStruct(A=0x4567, B=0x0123)
        let mut encoding_item = SszEncodingItem::new();
        let value = SmallTestStruct {
            a: 0x4567,
            b: 0x0123,
        };
        value.encode_to(&mut encoding_item);
        assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), "67452301");
    }

    #[test]
    fn test_small_test_struct_decoding() {
        let data = [(
            "67452301",
            Ok(SmallTestStruct {
                a: 0x4567,
                b: 0x0123,
            }),
        )];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(SmallTestStruct::decode_from(&decoding_item), result);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct SmallTestStruct {
        a: u16,
        b: u16,
    }

    impl SszType for SmallTestStruct {
        fn size() -> Option<u32> {
            Some(u16::size().unwrap() + u16::size().unwrap())
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut encoding_item = SszEncodingItem::new();

            encoding_item.encode_as_container_element(&self.a);
            encoding_item.encode_as_container_element(&self.b);
            encoding_item.take_data()
        }

        fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
            let decoding_item = SszDecodingItem::new_from_data(bytes).unwrap();
            let sizes = [u16::size(), u16::size()];
            let items = decoding_item.decode_as_items(&sizes)?;
            let mut iter = items.iter();

            let a = u16::decode_from(iter.next().unwrap())?;
            let b = u16::decode_from(iter.next().unwrap())?;
            Ok(SmallTestStruct { a, b })
        }
    }

    #[test]
    fn test_single_field_test_struct_encoding() {
        // class SingleFieldTestStruct(Container):
        //     A: byte
        //
        // SingleFieldTestStruct(A=0xab)
        let mut encoding_item = SszEncodingItem::new();
        let value = SingleFieldTestStruct { a: 0xab };
        value.encode_to(&mut encoding_item);
        assert_eq!(bytes_to_lower_hex(&encoding_item.take_data()), "ab");
    }

    #[test]
    fn test_single_field_test_struct_decoding() {
        let data = [("ab", Ok(SingleFieldTestStruct { a: 0xab }))];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(SingleFieldTestStruct::decode_from(&decoding_item), result);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct SingleFieldTestStruct {
        a: u8,
    }

    impl SszType for SingleFieldTestStruct {
        fn size() -> Option<u32> {
            u8::size()
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut encoding_item = SszEncodingItem::new();

            encoding_item.encode_as_container_element(&self.a);
            encoding_item.take_data()
        }

        fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
            let decoding_item = SszDecodingItem::new_from_data(bytes).unwrap();
            let sizes = [u8::size()];
            let items = decoding_item.decode_as_items(&sizes)?;
            let mut iter = items.iter();

            let a = u8::decode_from(iter.next().unwrap())?;
            Ok(SingleFieldTestStruct { a })
        }
    }

    #[test]
    fn test_fixed_test_struct_encoding() {
        // class FixedTestStruct(Container):
        //     A: uint8
        //     B: uint64
        //     C: uint32
        //
        // FixedTestStruct(A=0xab, B=0xaabbccdd00112233, C=0x12345678)
        let mut encoding_item = SszEncodingItem::new();
        let value = FixedTestStruct {
            a: 0xab,
            b: 0xaabbccdd00112233,
            c: 0x12345678,
        };
        value.encode_to(&mut encoding_item);
        assert_eq!(
            bytes_to_lower_hex(&encoding_item.take_data()),
            "ab33221100ddccbbaa78563412"
        );
    }

    #[test]
    fn test_fixed_test_struct_decoding() {
        let data = [(
            "ab33221100ddccbbaa78563412",
            Ok(FixedTestStruct {
                a: 0xab,
                b: 0xaabbccdd00112233,
                c: 0x12345678,
            }),
        )];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(FixedTestStruct::decode_from(&decoding_item), result);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FixedTestStruct {
        a: u8,
        b: u64,
        c: u32,
    }

    impl SszType for FixedTestStruct {
        fn size() -> Option<u32> {
            Some(u8::size().unwrap() + u64::size().unwrap() + u32::size().unwrap())
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut encoding_item = SszEncodingItem::new();

            encoding_item.encode_as_container_element(&self.a);
            encoding_item.encode_as_container_element(&self.b);
            encoding_item.encode_as_container_element(&self.c);
            encoding_item.take_data()
        }

        fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
            let decoding_item = SszDecodingItem::new_from_data(bytes).unwrap();
            let sizes = [u8::size(), u64::size(), u32::size()];
            let items = decoding_item.decode_as_items(&sizes)?;
            let mut iter = items.iter();

            let a = u8::decode_from(iter.next().unwrap())?;
            let b = u64::decode_from(iter.next().unwrap())?;
            let c = u32::decode_from(iter.next().unwrap())?;
            Ok(FixedTestStruct { a, b, c })
        }
    }

    #[test]
    fn test_var_test_struct_encoding() {
        // class VarTestStruct(Container):
        //     A: uint16
        //     B: List[uint16, 1024]
        //     C: uint8
        //
        // VarTestStruct(A=0xabcd, B=List[uint16, 1024](), C=0xff)
        let mut encoding_item = SszEncodingItem::new();
        let value = VarTestStruct {
            a: 0xabcd,
            b: vec![],
            c: 0xff,
        };
        value.encode_to(&mut encoding_item);
        assert_eq!(
            bytes_to_lower_hex(&encoding_item.take_data()),
            "cdab07000000ff"
        );

        // VarTestStruct(A=0xabcd, B=List[uint16, 1024](1, 2, 3), C=0xff)
        let mut encoding_item = SszEncodingItem::new();
        let value = VarTestStruct {
            a: 0xabcd,
            b: vec![1, 2, 3],
            c: 0xff,
        };
        value.encode_to(&mut encoding_item);
        assert_eq!(
            bytes_to_lower_hex(&encoding_item.take_data()),
            "cdab07000000ff010002000300"
        );
    }

    #[test]
    fn test_var_test_struct_decoding() {
        let data = [(
            "cdab07000000ff010002000300",
            Ok(VarTestStruct {
                a: 0xabcd,
                b: vec![1, 2, 3],
                c: 0xff,
            }),
        )];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(VarTestStruct::decode_from(&decoding_item), result);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct VarTestStruct {
        a: u16,
        b: Vec<u16>,
        c: u8,
    }

    impl SszType for VarTestStruct {
        fn size() -> Option<u32> {
            None
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut encoding_item = SszEncodingItem::new();

            encoding_item.encode_as_container_element(&self.a);
            encoding_item.encode_as_container_element(&self.b);
            encoding_item.encode_as_container_element(&self.c);
            encoding_item.take_data()
        }

        fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
            let decoding_item = SszDecodingItem::new_from_data(bytes).unwrap();
            let sizes = [u16::size(), Vec::<u16>::size(), u8::size()];
            let items = decoding_item.decode_as_items(&sizes)?;
            let mut iter = items.iter();

            let a = u16::decode_from(iter.next().unwrap())?;
            let b = Vec::<u16>::decode_from(iter.next().unwrap())?;
            let c = u8::decode_from(iter.next().unwrap())?;
            Ok(VarTestStruct { a, b, c })
        }
    }

    #[test]
    fn test_complex_test_struct_encoding() {
        // class ComplexTestStruct(Container):
        //     A: uint16
        //     B: List[uint16, 128]
        //     C: uint8
        //     D: List[byte, 256]
        //     E: VarTestStruct
        //     F: Vector[FixedTestStruct, 4]
        //     G: Vector[VarTestStruct, 2]
        //
        // ComplexTestStruct(
        //          A=0xaabb,
        //          B=List[uint16, 128](0x1122, 0x3344),
        //          C=0xff,
        //          D=List[byte, 256](b"foobar"),
        //          E=VarTestStruct(A=0xabcd, B=List[uint16, 1024](1, 2, 3), C=0xff),
        //          F=Vector[FixedTestStruct, 4](
        //              FixedTestStruct(A=0xcc, B=0x4242424242424242, C=0x13371337),
        //              FixedTestStruct(A=0xdd, B=0x3333333333333333, C=0xabcdabcd),
        //              FixedTestStruct(A=0xee, B=0x4444444444444444, C=0x00112233),
        //              FixedTestStruct(A=0xff, B=0x5555555555555555, C=0x44556677)),
        //          G=Vector[VarTestStruct, 2](
        //              VarTestStruct(A=0xdead, B=List[uint16, 1024](1, 2, 3), C=0x11),
        //              VarTestStruct(A=0xbeef, B=List[uint16, 1024](4, 5, 6), C=0x22)),
        //      )
        let mut encoding_item = SszEncodingItem::new();
        let value = ComplexTestStruct {
            a: 0xaabb,
            b: vec![0x1122, 0x3344],
            c: 0xff,
            d: "foobar".as_bytes().to_vec(),
            e: VarTestStruct {
                a: 0xabcd,
                b: vec![1, 2, 3],
                c: 0xff,
            },
            f: [
                FixedTestStruct {
                    a: 0xcc,
                    b: 0x4242424242424242,
                    c: 0x13371337,
                },
                FixedTestStruct {
                    a: 0xdd,
                    b: 0x3333333333333333,
                    c: 0xabcdabcd,
                },
                FixedTestStruct {
                    a: 0xee,
                    b: 0x4444444444444444,
                    c: 0x00112233,
                },
                FixedTestStruct {
                    a: 0xff,
                    b: 0x5555555555555555,
                    c: 0x44556677,
                },
            ],
            g: [
                VarTestStruct {
                    a: 0xdead,
                    b: vec![1, 2, 3],
                    c: 0x11,
                },
                VarTestStruct {
                    a: 0xbeef,
                    b: vec![4, 5, 6],
                    c: 0x22,
                },
            ],
        };
        value.encode_to(&mut encoding_item);
        assert_eq!(
            bytes_to_lower_hex(&encoding_item.take_data()),
            concat!(
                "bbaa",
                "47000000", // offset of B, []uint16
                "ff",
                "4b000000", // offset of foobar
                "51000000", // offset of E
                "cc424242424242424237133713",
                "dd3333333333333333cdabcdab",
                "ee444444444444444433221100",
                "ff555555555555555577665544",
                "5e000000",                   // pointer to G
                "22114433",                   // contents of B
                "666f6f626172",               // foobar
                "cdab07000000ff010002000300", // contents of E
                "08000000",
                "15000000", // [start G]: local offsets of [2]varTestStruct
                "adde0700000011010002000300",
                "efbe0700000022040005000600",
            )
        );
    }

    #[test]
    fn test_complex_test_struct_decoding() {
        let data = [(
            concat!(
                "bbaa",
                "47000000", // offset of B, []uint16
                "ff",
                "4b000000", // offset of foobar
                "51000000", // offset of E
                "cc424242424242424237133713",
                "dd3333333333333333cdabcdab",
                "ee444444444444444433221100",
                "ff555555555555555577665544",
                "5e000000",                   // pointer to G
                "22114433",                   // contents of B
                "666f6f626172",               // foobar
                "cdab07000000ff010002000300", // contents of E
                "08000000",
                "15000000", // [start G]: local offsets of [2]varTestStruct
                "adde0700000011010002000300",
                "efbe0700000022040005000600",
            ),
            Ok(ComplexTestStruct {
                a: 0xaabb,
                b: vec![0x1122, 0x3344],
                c: 0xff,
                d: "foobar".as_bytes().to_vec(),
                e: VarTestStruct {
                    a: 0xabcd,
                    b: vec![1, 2, 3],
                    c: 0xff,
                },
                f: [
                    FixedTestStruct {
                        a: 0xcc,
                        b: 0x4242424242424242,
                        c: 0x13371337,
                    },
                    FixedTestStruct {
                        a: 0xdd,
                        b: 0x3333333333333333,
                        c: 0xabcdabcd,
                    },
                    FixedTestStruct {
                        a: 0xee,
                        b: 0x4444444444444444,
                        c: 0x00112233,
                    },
                    FixedTestStruct {
                        a: 0xff,
                        b: 0x5555555555555555,
                        c: 0x44556677,
                    },
                ],
                g: [
                    VarTestStruct {
                        a: 0xdead,
                        b: vec![1, 2, 3],
                        c: 0x11,
                    },
                    VarTestStruct {
                        a: 0xbeef,
                        b: vec![4, 5, 6],
                        c: 0x22,
                    },
                ],
            }),
        )];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(ComplexTestStruct::decode_from(&decoding_item), result);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ComplexTestStruct {
        a: u16,
        b: Vec<u16>,
        c: u8,
        d: Vec<u8>,
        e: VarTestStruct,
        f: [FixedTestStruct; 4],
        g: [VarTestStruct; 2],
    }

    impl SszType for ComplexTestStruct {
        fn size() -> Option<u32> {
            None
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut encoding_item = SszEncodingItem::new();

            encoding_item.encode_as_container_element(&self.a);
            encoding_item.encode_as_container_element(&self.b);
            encoding_item.encode_as_container_element(&self.c);
            encoding_item.encode_as_container_element(&self.d);
            encoding_item.encode_as_container_element(&self.e);
            encoding_item.encode_as_container_element(&self.f);
            encoding_item.encode_as_container_element(&self.g);
            encoding_item.take_data()
        }

        fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
            let decoding_item = SszDecodingItem::new_from_data(bytes).unwrap();
            let sizes = [
                u16::size(),
                Vec::<u16>::size(),
                u8::size(),
                Vec::<u8>::size(),
                VarTestStruct::size(),
                <[FixedTestStruct; 4]>::size(),
                <[VarTestStruct; 2]>::size(),
            ];
            let items = decoding_item.decode_as_items(&sizes)?;
            let mut iter = items.iter();

            let a = u16::decode_from(iter.next().unwrap())?;
            let b = Vec::<u16>::decode_from(iter.next().unwrap())?;
            let c = u8::decode_from(iter.next().unwrap())?;
            let d = Vec::<u8>::decode_from(iter.next().unwrap())?;
            let e = VarTestStruct::decode_from(iter.next().unwrap())?;
            let f = <[FixedTestStruct; 4]>::decode_from(iter.next().unwrap())?;
            let g = <[VarTestStruct; 2]>::decode_from(iter.next().unwrap())?;
            Ok(ComplexTestStruct {
                a,
                b,
                c,
                d,
                e,
                f,
                g,
            })
        }
    }

    #[test]
    fn test_array_of_var_test_struct2_encoding() {
        // class VarTestStruct2(Container):
        //     A: uint16
        //     B: List[uint16, 1024]
        //     C: List[uint16, 1024]
        //     D: uint8
        //
        // Vector[VarTestStruct2, 2](
        //     VarTestStruct2(A=0xabcd, B=List[uint16, 1024](), C=List[uint16, 1024](0xef,), D=0xff),
        //     VarTestStruct2(A=0xabcd, B=List[uint16, 1024](), C=List[uint16, 1024](0xef,), D=0xff),
        // )
        let mut encoding_item = SszEncodingItem::new();
        let value = [
            VarTestStruct2 {
                a: 0xabcd,
                b: vec![],
                c: vec![0xef],
                d: 0xff,
            },
            VarTestStruct2 {
                a: 0xabcd,
                b: vec![],
                c: vec![0xef],
                d: 0xff,
            },
        ];
        value.encode_to(&mut encoding_item);
        assert_eq!(
            bytes_to_lower_hex(&encoding_item.take_data()),
            "0800000015000000cdab0b0000000b000000ffef00cdab0b0000000b000000ffef00"
        );
    }

    #[test]
    fn test_var_test_struct2_decoding() {
        let data = [
            (
                "cdab0b0000000b000000ffef00",
                Ok(VarTestStruct2 {
                    a: 0xabcd,
                    b: vec![],
                    c: vec![0xef],
                    d: 0xff,
                }),
            ),
            (
                "cdab0b0000000b000000",
                Err(SszDataDecodingError::InvalidFormat),
            ), // container: bytes_len < headers_len
            (
                "cdab0c0000000b000000ffef00",
                Err(SszDataDecodingError::InvalidFormat),
            ), // container: offset > previous_offset_rev
            (
                "cdabff0000000b000000ffef00",
                Err(SszDataDecodingError::InvalidFormat),
            ), // container: offset > previous_offset_rev
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(VarTestStruct2::decode_from(&decoding_item), result);
        }
    }

    #[test]
    fn test_array_of_var_test_struct2_decoding() {
        let data = [
            (
                "0800000015000000cdab0b0000000b000000ffef00cdab0b0000000b000000ffef00",
                Ok([
                    VarTestStruct2 {
                        a: 0xabcd,
                        b: vec![],
                        c: vec![0xef],
                        d: 0xff,
                    },
                    VarTestStruct2 {
                        a: 0xabcd,
                        b: vec![],
                        c: vec![0xef],
                        d: 0xff,
                    },
                ]),
            ),
            ("08000000150000", Err(SszDataDecodingError::InvalidFormat)), // array: bytes_len < headers_len
            (
                "0800000006000000cdab0b0000000b000000ffef00cdab0b0000000b000000ffef00",
                Err(SszDataDecodingError::InvalidFormat),
            ), // array: offset < previous_offset
            (
                "ff00000006000000cdab0b0000000b000000ffef00cdab0b0000000b000000ffef00",
                Err(SszDataDecodingError::InvalidFormat),
            ), // array: offset > bytes_len
        ];
        for (hex, result) in data {
            let data = hex_to_bytes(hex).unwrap();
            let decoding_item = SszDecodingItem::new_from_data(&data).unwrap();
            assert_eq!(<[VarTestStruct2; 2]>::decode_from(&decoding_item), result);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct VarTestStruct2 {
        a: u16,
        b: Vec<u16>,
        c: Vec<u16>,
        d: u8,
    }

    impl SszType for VarTestStruct2 {
        fn size() -> Option<u32> {
            None
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut encoding_item = SszEncodingItem::new();

            encoding_item.encode_as_container_element(&self.a);
            encoding_item.encode_as_container_element(&self.b);
            encoding_item.encode_as_container_element(&self.c);
            encoding_item.encode_as_container_element(&self.d);
            encoding_item.take_data()
        }

        fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
            let decoding_item = SszDecodingItem::new_from_data(bytes).unwrap();
            let sizes = [
                u16::size(),
                Vec::<u16>::size(),
                Vec::<u16>::size(),
                u8::size(),
            ];
            let items = decoding_item.decode_as_items(&sizes)?;
            let mut iter = items.iter();

            let a = u16::decode_from(iter.next().unwrap())?;
            let b = Vec::<u16>::decode_from(iter.next().unwrap())?;
            let c = Vec::<u16>::decode_from(iter.next().unwrap())?;
            let d = u8::decode_from(iter.next().unwrap())?;
            Ok(VarTestStruct2 { a, b, c, d })
        }
    }
}
