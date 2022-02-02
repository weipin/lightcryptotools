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

/// Converts `bytes` into a lowercase hexadecimal representation.
///
/// Each byte is converted into the corresponding 2-digit hex representation.
///
/// # Examples
///
/// ```
/// use lightcryptotools::crypto::bytes_to_hex;
///
/// let hex = bytes_to_hex(&[0x13, 0x7a, 0xcf]);
/// assert_eq!(hex, "137acf");
/// ```
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    // 1 byte expands to 2 corresponding UTF8 chars.
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
        //     Using ``>> 7`` on lhs_i8 extracts the sign, thanks to sign extension.
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
        data.push((87 + high_nibble + (((high_nibble - 10) >> 7) & -39)) as u8);
        data.push((87 + low_nibble + (((low_nibble - 10) >> 7) & -39)) as u8);
    }

    unsafe { String::from_utf8_unchecked(data) }
}
