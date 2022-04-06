// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Constant-time implementation for hex/bytes conversion.
//!
//! From time to time, your colleagues pass down some [mysterious code snippets][1] that
//! you can copy and paste into your project, and they just work.
//! This implementation is one of them.
//! The same code can be found in [libsodium][2] and [WireGuard][3].
//! Original code by [CodesInChaos][4].
//!
//! [1]: https://www.reddit.com/r/HalfLife/comments/nwrtol/valve_still_uses_the_same_light_flicker_pattern/
//! [2]: https://github.com/jedisct1/libsodium/blob/64129657a5c67f3bab84562aa8d57dacc685cc75/src/libsodium/sodium/codecs.c#L12-L101
//! [3]: https://git.zx2c4.com/wireguard-tools/tree/src/encoding.c?id=d8230ea0dcb02d716125b2b3c076f2de40ebed99#n74
//! [4]: https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa#answer-14333437

use std::fmt;
use std::fmt::Display;

/// Returns lowercase hexadecimal representation of `bytes`.
///
/// Each byte is converted into the corresponding 2-digit hex representation.
///
/// # Examples
///
/// ```
/// use lightcryptotools::crypto::codecs::bytes_to_hex;
///
/// let hex = bytes_to_hex(&[0x13, 0x7a, 0xcf]);
/// assert_eq!(hex, "137acf");
/// ```
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    // 1 byte expands to 2 corresponding hexadecimal digits.
    let mut data = Vec::with_capacity(bytes.len() * 2);

    for byte in bytes {
        let low_nibble = (byte & 0x0f) as i8;
        let high_nibble = (byte >> 4) as i8;

        // A nibble is 4 bits, representing [0x0, 0xf]
        //
        // 1. `nibble - 10`:
        //
        //     The result is < 0 for nibble in [0x0, 0x9] (char: 0-9),
        //     and >= 0 for nibble in [0xa, 0xf] (char: a-f)
        //
        // 2. ``lhs_i8 >> 7``:
        //
        //     Using ``>> 7`` on lhs_i8 extracts the sign[^1].
        //     The result is -1 for lhs_i8 < 0, and 0 for lhs_i8 >= 0.
        //
        // 3. Combining 1 and 2, `(nibble - 10) >> 7`:
        //    The result is -1 for nibble in [0x0, 0x9], and 0 for nibble in [0xa, 0xf]
        //
        // 4. `-1 & -39` and `0 & -39`:
        //
        //     The result is -39 for `-1 & -39`, 0 for `0 & -39`
        //
        // 5. `87 + nibble + (-39)` or `87 + nibble + 0`:
        //
        //     Combining 3 and 4,
        //     the result is [48, 57] for [0x0, 0x9], and [97, 102] for [0xa, 0xf].
        //     In ASCII, [48, 57] represents chars '0' to '9',
        //     and [97, 102] represents chars 'a' to 'f'.
        //
        // [^1]: `>>` performs arithmetic right shift on signed integer types.
        //     https://doc.rust-lang.org/reference/expressions/operator-expr.html#arithmetic-and-logical-binary-operators
        data.push((87 + high_nibble + (((high_nibble - 10) >> 7) & -39)) as u8);
        data.push((87 + low_nibble + (((low_nibble - 10) >> 7) & -39)) as u8);
    }

    unsafe { String::from_utf8_unchecked(data) }
}

/// Returns bytes represented by the hexadecimal string `hex`.
///
/// `hex` is a string composed of hexadecimal digits: [0-9a-fA-F].
///
/// # Errors
///
/// Will return an error if:
/// - `hex` contains non-hexadecimal digits.
/// - The len of `hex` isn't even.
///
/// # Examples
///
/// ```
/// use lightcryptotools::crypto::codecs::hex_to_bytes;
///
/// let bytes = hex_to_bytes("137acf").unwrap();
/// assert_eq!(bytes, &[0x13, 0x7a, 0xcf]);
/// ```
pub fn hex_to_bytes<T: AsRef<[u8]>>(hex: T) -> Result<Vec<u8>, CodecsError> {
    let hex = hex.as_ref();
    let hex_len_is_even = { hex.len() & 1 == 0 };
    if !hex_len_is_even {
        return Err(CodecsError::NotByteAligned);
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.chunks_exact(2) {
        let c = chunk[0] as u16;

        // The result is [0, 9] for `c` in [48, 57],
        // and > 9 for the rest.
        let c_num = c ^ 48;

        // The result is 0xff for `c_num` in [0, 9],
        // and 0 for the rest.
        let c_num0 = c_num.wrapping_sub(10) >> 8;

        // The result is [10, 15] for `c` in both [65, 70] and [97, 102].
        let c_alpha = (c & !32).wrapping_sub(55);

        // 1. `c_alpha.wrapping_sub(10)`:
        //
        //     The result is [0, 5] for `c_alpha` in [10, 15].
        //
        // 2. `c_alpha.wrapping_sub(16)`:
        //
        //     The result is [0xfffa, 0xffff] for `c_alpha` in [10, 15].
        //
        // 3. `(c_alpha.wrapping_sub(10) ^ c_alpha.wrapping_sub(16)) >> 8`
        //
        //     The result is 0xff for `c_alpha` in both [65, 70] and [97, 102],
        //     and 0 for the rest.
        let c_alpha0 = (c_alpha.wrapping_sub(10) ^ c_alpha.wrapping_sub(16)) >> 8;

        if (c_num0 | c_alpha0) == 0 {
            return Err(CodecsError::InvalidCharFound);
        }
        let c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
        let mut c_acc = (c_val as u8) << 4;

        let c = chunk[1] as u16;
        let c_num = c ^ 48;
        let c_num0 = c_num.wrapping_sub(10) >> 8;
        let c_alpha = (c & !32).wrapping_sub(55);
        let c_alpha0 = (c_alpha.wrapping_sub(10) ^ c_alpha.wrapping_sub(16)) >> 8;
        if (c_num0 | c_alpha0) == 0 {
            return Err(CodecsError::InvalidCharFound);
        }
        let c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
        c_acc |= c_val as u8;

        bytes.push(c_acc);
    }

    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum CodecsError {
    InvalidCharFound,
    NotByteAligned,
}

impl Display for CodecsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecsError::InvalidCharFound => write!(f, "Invalid char found"),
            CodecsError::NotByteAligned => write!(f, "Not 1-byte aligned"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing_tools::quickcheck::HexString;
    use ::quickcheck_macros::quickcheck;

    #[test]
    fn empty_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[]).is_empty(), true);
    }

    #[test]
    fn empty_hex_to_bytes() {
        assert_eq!(hex_to_bytes("").unwrap().is_empty(), true);
    }

    #[test]
    fn hex_to_bytes_not_byte_aligned() {
        let err = hex_to_bytes("d559b").unwrap_err();
        assert_eq!(err, CodecsError::NotByteAligned);
    }

    #[test]
    fn hex_to_bytes_invalid_char_found() {
        let err = hex_to_bytes("d55G9b").unwrap_err();
        assert_eq!(err, CodecsError::InvalidCharFound);
    }

    #[test]
    fn byte_values_double_conversion() {
        // For each value in [0, 255] as one byte,
        // converts the byte to hex and back again.
        let mut count = 0;
        for i in u8::MIN..=u8::MAX {
            let hex = bytes_to_hex(&[i]);
            let byte = hex_to_bytes(&hex).unwrap()[0];
            assert_eq!(i, byte);

            count += 1;
        }
        assert_eq!(count, 256);
    }

    #[test]
    fn hex_to_bytes_input_char_validation_check() {
        // Goes through all the combinations for a two-character string,
        // and feeds the strings to `hex_to_bytes`.
        // Should return `CodecsError::InvalidCharFound` for any character not in [0-9a-fA-F].
        for i in u8::MIN..=u8::MAX {
            for j in u8::MIN..=u8::MAX {
                let bytes = [i, j];
                let hex = unsafe { std::str::from_utf8_unchecked(&bytes) };

                if i.is_ascii_hexdigit() && j.is_ascii_hexdigit() {
                    assert_eq!(
                        bytes_to_hex(&hex_to_bytes(hex).unwrap()),
                        hex.to_lowercase()
                    )
                } else {
                    let err = hex_to_bytes(hex).unwrap_err();
                    assert_eq!(err, CodecsError::InvalidCharFound);
                }
            }
        }
    }

    #[quickcheck]
    fn hex_to_bytes_double_conversion(hex: HexString) -> bool {
        let bytes = hex_to_bytes(&hex.0).unwrap();
        bytes_to_hex(&bytes) == hex.0.to_lowercase()
    }
}
