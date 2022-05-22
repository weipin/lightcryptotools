// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

///! Implements SHA-3 (FIPS PUB 202)
///
/// This implementation is a port of [tiny_sha3][1].
/// Also, manually "unrolled" a significant part of the loops in `sha3_keccakf`,
/// exchanging readability and code size for performance.
///
/// [1]: https://github.com/mjosaarinen/tiny_sha3
use std::iter::zip;
use std::mem::size_of;

pub(crate) fn sha3_digest(
    message: &[u8],
    s: &mut KeccakfState,
    output_byte_size: usize,
    delimiter_suffix: u8,
) -> Vec<u8> {
    s.fill(0);

    let rate_byte_size = KECCAKF_WIDTH_BYTE_SIZE - 2 * output_byte_size;
    debug_assert!(rate_byte_size % size_of::<u64>() == 0);

    // Handles "complete" chunks(blocks).
    let mut chunks = message.chunks_exact(rate_byte_size);
    for block in chunks.by_ref() {
        for (bytes, s_iter) in zip(block.chunks_exact(size_of::<u64>()), s.iter_mut()) {
            // Creates a u64 from its memory representation in native endian,
            // meaning that the representation is left as it is regardless of the target platform's endianness.
            // The memory representation is specified by `bytes` as a byte array.
            *s_iter ^= u64::from_ne_bytes(bytes.try_into().unwrap());
        }
        sha3_keccakf(s);
    }

    // Handles the remaining chunk(block) which could be empty.
    let s_bytes: &mut [u8; KECCAKF_WIDTH_BYTE_SIZE] = unsafe { core::mem::transmute(s) };
    let block = chunks.remainder();
    if block.is_empty() {
        s_bytes[0] ^= delimiter_suffix;
    } else {
        let mut s_bytes_iter = s_bytes.iter_mut();
        for &byte in block {
            *s_bytes_iter.next().unwrap() ^= byte;
        }
        *s_bytes_iter.next().unwrap() ^= delimiter_suffix;
    }
    s_bytes[rate_byte_size - 1] ^= 0x80;

    let s: &mut KeccakfState = unsafe { core::mem::transmute(s_bytes) };
    sha3_keccakf(s);

    let s_bytes: &mut [u8; KECCAKF_WIDTH_BYTE_SIZE] = unsafe { core::mem::transmute(s) };
    s_bytes[..output_byte_size].to_vec()
}

fn sha3_keccakf(s: &mut KeccakfState) {
    let mut bc = [0_u64; 5];

    #[cfg(target_endian = "big")]
    for e in s.iter_mut() {
        *e = e.swap_bytes();
    }

    #[allow(clippy::needless_range_loop)]
    for r in 0..KECCAKF_ROUNDS {
        // Theta
        //
        // for i in 0..5 {
        //     bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        // }
        theta_step1_iteration!(bc, s, 0, 5, 10, 15, 20);
        theta_step1_iteration!(bc, s, 1, 6, 11, 16, 21);
        theta_step1_iteration!(bc, s, 2, 7, 12, 17, 22);
        theta_step1_iteration!(bc, s, 3, 8, 13, 18, 23);
        theta_step1_iteration!(bc, s, 4, 9, 14, 19, 24);

        // for i in 0..5 {
        //     t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
        //     for j in (0..25).step_by(5) {
        //         s[j + i] ^= t;
        //     }
        // }
        theta_step2_iteration!(bc, s, 0, 4, 1, 5, 10, 15, 20);
        theta_step2_iteration!(bc, s, 1, 0, 2, 6, 11, 16, 21);
        theta_step2_iteration!(bc, s, 2, 1, 3, 7, 12, 17, 22);
        theta_step2_iteration!(bc, s, 3, 2, 4, 8, 13, 18, 23);
        theta_step2_iteration!(bc, s, 4, 3, 0, 9, 14, 19, 24);

        // Rho Pi
        // t = s[1];
        // for i in 0..24 {
        //     let j = KECCAKF_PILN[i];
        //     bc[0] = s[j];
        //     s[j] = t.rotate_left(KECCAKF_ROTC[i]);
        //     t = bc[0];
        // }
        rho_pi_iteration!(bc, s, s[1], 0);
        rho_pi_iteration!(bc, s, bc[0], 1);
        rho_pi_iteration!(bc, s, bc[0], 2);
        rho_pi_iteration!(bc, s, bc[0], 3);
        rho_pi_iteration!(bc, s, bc[0], 4);
        rho_pi_iteration!(bc, s, bc[0], 5);
        rho_pi_iteration!(bc, s, bc[0], 6);
        rho_pi_iteration!(bc, s, bc[0], 7);
        rho_pi_iteration!(bc, s, bc[0], 8);
        rho_pi_iteration!(bc, s, bc[0], 9);
        rho_pi_iteration!(bc, s, bc[0], 10);
        rho_pi_iteration!(bc, s, bc[0], 11);
        rho_pi_iteration!(bc, s, bc[0], 12);
        rho_pi_iteration!(bc, s, bc[0], 13);
        rho_pi_iteration!(bc, s, bc[0], 14);
        rho_pi_iteration!(bc, s, bc[0], 15);
        rho_pi_iteration!(bc, s, bc[0], 16);
        rho_pi_iteration!(bc, s, bc[0], 17);
        rho_pi_iteration!(bc, s, bc[0], 18);
        rho_pi_iteration!(bc, s, bc[0], 19);
        rho_pi_iteration!(bc, s, bc[0], 20);
        rho_pi_iteration!(bc, s, bc[0], 21);
        rho_pi_iteration!(bc, s, bc[0], 22);
        rho_pi_iteration!(bc, s, bc[0], 23);

        //  Chi
        // for j in (0..25).step_by(5) {
        //     bc[..5].copy_from_slice(&s[j..(5 + j)]);
        //     for i in 0..5 {
        //         s[j + i] ^= (!bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        //     }
        // }
        chi_iteration!(bc, s, 0);
        chi_iteration!(bc, s, 5);
        chi_iteration!(bc, s, 10);
        chi_iteration!(bc, s, 15);
        chi_iteration!(bc, s, 20);

        //  Iota
        s[0] ^= KECCAKF_RNDC[r];
    }

    #[cfg(target_endian = "big")]
    for e in s.iter_mut() {
        *e = e.swap_bytes();
    }
}

pub(crate) type KeccakfState = [u64; 25];

pub(crate) const KECCAKF_WIDTH_BYTE_SIZE: usize = 200; // `1600 / u8::BITS`
pub(crate) const KECCAKF_ROUNDS: usize = 24;

pub(crate) const KECCAK_DELIMITER_SUFFIX_KECCAK: u8 = 0x01;
pub(crate) const KECCAK_DELIMITER_SUFFIX_SHA3: u8 = 0x06;

#[rustfmt::skip]
static KECCAKF_RNDC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

static KECCAKF_ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

static KECCAKF_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

// bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20]; // for i in [0, 5)
macro_rules! theta_step1_iteration {
    ($bc:ident, $s:ident, $i:literal, $i_5:literal, $i_10:literal, $i_15:literal, $i_20:literal) => {
        $bc[$i] = $s[$i] ^ $s[$i_5] ^ $s[$i_10] ^ $s[$i_15] ^ $s[$i_20];
    };
}
use theta_step1_iteration;

// for i in [0, 5)
// ```
// t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
// for j in (0..25).step_by(5) {
//     s[j + i] ^= t;
// }
// ```
macro_rules! theta_step2_iteration {
    ($bc:ident, $s:ident, $i:literal,
    $i_4_rem_5:literal, $i_1_rem_5:literal,
    $i_5:literal, $i_10:literal, $i_15:literal, $i_20:literal) => {
        let t = $bc[$i_4_rem_5] ^ $bc[$i_1_rem_5].rotate_left(1);
        $s[$i] ^= t;
        $s[$i_5] ^= t;
        $s[$i_10] ^= t;
        $s[$i_15] ^= t;
        $s[$i_20] ^= t;
    };
}
use theta_step2_iteration;

// for i in [0, 24)
// ```
// let j = KECCAKF_PILN[i];
// bc[0] = s[j];
// s[j] = t.rotate_left(KECCAKF_ROTC[i]);
// ```
macro_rules! rho_pi_iteration {
    ($bc:ident, $s:ident, $t:expr, $i: literal) => {
        let t = $t;
        let j = KECCAKF_PILN[$i];
        $bc[0] = $s[j];
        $s[j] = t.rotate_left(KECCAKF_ROTC[$i]);
    };
}
use rho_pi_iteration;

// for j in [0, 5, 10, 15, 20]
// ```
// bc[..5].copy_from_slice(&s[j..(5 + j)]);
// for i in 0..5 {
//     s[j + i] ^= (!bc[(i + 1) % 5]) & bc[(i + 2) % 5];
// }
// ```
macro_rules! chi_iteration {
    ($bc:ident, $s:ident, $j:literal) => {
        $bc[..5].copy_from_slice(&$s[$j..(5 + $j)]);

        $s[$j] ^= (!$bc[1]) & $bc[2];
        $s[$j + 1] ^= (!$bc[2]) & $bc[3];
        $s[$j + 2] ^= (!$bc[3]) & $bc[4];
        $s[$j + 3] ^= (!$bc[4]) & $bc[0];
        $s[$j + 4] ^= (!$bc[0]) & $bc[1];
    };
}
use chi_iteration;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::{bytes_to_hex, hex_to_bytes};

    #[test]
    fn test_basic() {
        // message, output_byte_size, sha3_digest_hex, keccak_digest_hex,
        let data = [
            // SHA3-224, corner case with 0-length message
            (
                "",
                28,
                "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
                "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd",
            ),
            // SHA3-256, short message
            (
                "9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10",
                32,
                "2f1a5f7159e34ea19cddc70ebf9b81f1a66db40615d7ead3cc1f1b954d82a3af",
                "24dd2ee02482144f539f810d2caa8a7b75d0fa33657e47932122d273c3f6f6d1",
            ),
            // SHA3-384, exact block size
            (
                concat!(
                    "E35780EB9799AD4C77535D4DDB683CF33EF367715327CF4C4A58ED9CBDCDD486",
                    "F669F80189D549A9364FA82A51A52654EC721BB3AAB95DCEB4A86A6AFA93826D",
                    "B923517E928F33E3FBA850D45660EF83B9876ACCAFA2A9987A254B137C6E140A",
                    "21691E1069413848"
                ),
                48,
                concat!(
                    "d1c0fa85c8d183beff99ad9d752b263e286b477f79f0710b0103170173978133",
                    "44b99daf3bb7b1bc5e8d722bac85943a"
                ),
                concat!(
                    "9fb5700502e01926824f46e9f61894f9487dbcf8ae6217203c85606f97556653",
                    "9376d6239db04aef9bf48ca4f191a90b"
                ),
            ),
            // SHA3-512, multiblock message
            (
                concat!(
                    "3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F5",
                    "623CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A",
                    "15358F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0",
                    "A3D84A2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764",
                    "B2F83AADC66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43",
                    "C70088B6183639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D",
                    "817FC2534A52F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E08",
                    "5172E328807C02D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1"
                ),
                64,
                concat!(
                    "6e8b8bd195bdd560689af2348bdc74ab7cd05ed8b9a57711e9be71e9726fda45",
                    "91fee12205edacaf82ffbbaf16dff9e702a708862080166c2ff6ba379bc7ffc2"
                ),
                concat!(
                    "81950e7096d31d4f22e3db71cac725bf59e81af54c7ca9e6aeee71c010fc5467",
                    "466312a01aa5c137cfb140646941556796f612c9351268737c7e9a2b9631d1fa"
                ),
            ),
        ];

        let mut s = [0_64; 25];
        for (message, output_byte_size, sha3_digest_hex, keccak_digest_hex) in data {
            let digest = sha3_digest(
                &hex_to_bytes(message).unwrap(),
                &mut s,
                output_byte_size,
                KECCAK_DELIMITER_SUFFIX_SHA3,
            );
            assert_eq!(bytes_to_hex(&digest), sha3_digest_hex);

            let digest = sha3_digest(
                &hex_to_bytes(message).unwrap(),
                &mut s,
                output_byte_size,
                KECCAK_DELIMITER_SUFFIX_KECCAK,
            );
            assert_eq!(bytes_to_hex(&digest), keccak_digest_hex);
        }
    }
}
