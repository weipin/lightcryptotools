// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

///! Implements SHA-256
///
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
use super::core::calculate_k;
use super::core::rnd;
use crate::crypto::hash::core::UnkeyedHash;
use std::iter::zip;

pub struct Sha256 {
    // State
    s: [u32; 8],
    // Expanded message block
    w: [u32; 64],
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 {
            s: [0; 8],
            w: [0; 64],
        }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl UnkeyedHash for Sha256 {
    const INPUT_BLOCK_BYTE_LENGTH: usize = 64;
    const OUTPUT_BYTE_LENGTH: usize = 32;

    fn digest<T: AsRef<[u8]>>(&mut self, message: T) -> Vec<u8> {
        let result = sha256_digest(message.as_ref(), &mut self.s, &mut self.w);
        debug_assert_eq!(result.len(), Self::OUTPUT_BYTE_LENGTH);
        result
    }
}

fn sha256_digest(message: &[u8], s: &mut [u32; 8], w: &mut [u32; 64]) -> Vec<u8> {
    s.copy_from_slice(&S_SHA256);
    w.fill(0);

    let mut chunks = message.chunks_exact(Sha256::INPUT_BLOCK_BYTE_LENGTH);
    for block in chunks.by_ref() {
        sha256_block_compression(block, s, w);
    }

    let mut remaining = chunks.remainder().to_vec();
    // Pads the message
    // l: length of `message` in bits
    let l = u64::try_from(message.len()).unwrap() * 8;
    let k = calculate_k(l, Sha256::INPUT_BLOCK_BYTE_LENGTH as u64 * 8, 64);
    // Appends bit 1, 1-byte aligned
    remaining.push(0x80);
    // Appends zero bytes
    remaining.extend(&vec![0; (k - 7) as usize / 8]);
    // Appends `l` in binary representation
    remaining.extend(l.to_be_bytes());
    debug_assert!(
        remaining.len() == Sha256::INPUT_BLOCK_BYTE_LENGTH
            || remaining.len() == Sha256::INPUT_BLOCK_BYTE_LENGTH * 2
    );

    for block in remaining.chunks_exact(Sha256::INPUT_BLOCK_BYTE_LENGTH) {
        sha256_block_compression(block, s, w);
    }

    // output
    let mut digest = Vec::with_capacity(8 * std::mem::size_of::<u32>());
    for item in s {
        digest.extend(item.to_be_bytes());
    }
    digest
}

#[inline(always)]
fn sha256_block_compression(block: &[u8], s: &mut [u32; 8], w: &mut [u32; 64]) {
    // Loads the 64-byte message block into w[0..15] in big-endian order
    for (u32_bytes, w_iter) in zip(
        block.chunks_exact(std::mem::size_of::<u32>()),
        w[..16].iter_mut(),
    ) {
        *w_iter = u32::from_be_bytes(u32_bytes.try_into().unwrap());
    }

    // Expands the message block
    for i in 16..64 {
        w[i] = gamma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(gamma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    // Performs the compression
    let mut a = s[0];
    let mut b = s[1];
    let mut c = s[2];
    let mut d = s[3];
    let mut e = s[4];
    let mut f = s[5];
    let mut g = s[6];
    let mut h = s[7];

    // Exchanges readability and code size for slight performance improvement.
    // It's done by executing the compression without all of the variable swaps,
    // a trick learned from libtomcrypt[1]
    //
    // [1]: https://github.com/libtom/libtomcrypt/blob/7e7eb695d581782f04b24dc444cbfde86af59853/src/hashes/sha2/sha256.c#L107
    rnd!(a, b, c, d, e, f, g, h, w, 0, 0x428a2f98);
    rnd!(h, a, b, c, d, e, f, g, w, 1, 0x71374491);
    rnd!(g, h, a, b, c, d, e, f, w, 2, 0xb5c0fbcf);
    rnd!(f, g, h, a, b, c, d, e, w, 3, 0xe9b5dba5);
    rnd!(e, f, g, h, a, b, c, d, w, 4, 0x3956c25b);
    rnd!(d, e, f, g, h, a, b, c, w, 5, 0x59f111f1);
    rnd!(c, d, e, f, g, h, a, b, w, 6, 0x923f82a4);
    rnd!(b, c, d, e, f, g, h, a, w, 7, 0xab1c5ed5);
    rnd!(a, b, c, d, e, f, g, h, w, 8, 0xd807aa98);
    rnd!(h, a, b, c, d, e, f, g, w, 9, 0x12835b01);
    rnd!(g, h, a, b, c, d, e, f, w, 10, 0x243185be);
    rnd!(f, g, h, a, b, c, d, e, w, 11, 0x550c7dc3);
    rnd!(e, f, g, h, a, b, c, d, w, 12, 0x72be5d74);
    rnd!(d, e, f, g, h, a, b, c, w, 13, 0x80deb1fe);
    rnd!(c, d, e, f, g, h, a, b, w, 14, 0x9bdc06a7);
    rnd!(b, c, d, e, f, g, h, a, w, 15, 0xc19bf174);
    rnd!(a, b, c, d, e, f, g, h, w, 16, 0xe49b69c1);
    rnd!(h, a, b, c, d, e, f, g, w, 17, 0xefbe4786);
    rnd!(g, h, a, b, c, d, e, f, w, 18, 0x0fc19dc6);
    rnd!(f, g, h, a, b, c, d, e, w, 19, 0x240ca1cc);
    rnd!(e, f, g, h, a, b, c, d, w, 20, 0x2de92c6f);
    rnd!(d, e, f, g, h, a, b, c, w, 21, 0x4a7484aa);
    rnd!(c, d, e, f, g, h, a, b, w, 22, 0x5cb0a9dc);
    rnd!(b, c, d, e, f, g, h, a, w, 23, 0x76f988da);
    rnd!(a, b, c, d, e, f, g, h, w, 24, 0x983e5152);
    rnd!(h, a, b, c, d, e, f, g, w, 25, 0xa831c66d);
    rnd!(g, h, a, b, c, d, e, f, w, 26, 0xb00327c8);
    rnd!(f, g, h, a, b, c, d, e, w, 27, 0xbf597fc7);
    rnd!(e, f, g, h, a, b, c, d, w, 28, 0xc6e00bf3);
    rnd!(d, e, f, g, h, a, b, c, w, 29, 0xd5a79147);
    rnd!(c, d, e, f, g, h, a, b, w, 30, 0x06ca6351);
    rnd!(b, c, d, e, f, g, h, a, w, 31, 0x14292967);
    rnd!(a, b, c, d, e, f, g, h, w, 32, 0x27b70a85);
    rnd!(h, a, b, c, d, e, f, g, w, 33, 0x2e1b2138);
    rnd!(g, h, a, b, c, d, e, f, w, 34, 0x4d2c6dfc);
    rnd!(f, g, h, a, b, c, d, e, w, 35, 0x53380d13);
    rnd!(e, f, g, h, a, b, c, d, w, 36, 0x650a7354);
    rnd!(d, e, f, g, h, a, b, c, w, 37, 0x766a0abb);
    rnd!(c, d, e, f, g, h, a, b, w, 38, 0x81c2c92e);
    rnd!(b, c, d, e, f, g, h, a, w, 39, 0x92722c85);
    rnd!(a, b, c, d, e, f, g, h, w, 40, 0xa2bfe8a1);
    rnd!(h, a, b, c, d, e, f, g, w, 41, 0xa81a664b);
    rnd!(g, h, a, b, c, d, e, f, w, 42, 0xc24b8b70);
    rnd!(f, g, h, a, b, c, d, e, w, 43, 0xc76c51a3);
    rnd!(e, f, g, h, a, b, c, d, w, 44, 0xd192e819);
    rnd!(d, e, f, g, h, a, b, c, w, 45, 0xd6990624);
    rnd!(c, d, e, f, g, h, a, b, w, 46, 0xf40e3585);
    rnd!(b, c, d, e, f, g, h, a, w, 47, 0x106aa070);
    rnd!(a, b, c, d, e, f, g, h, w, 48, 0x19a4c116);
    rnd!(h, a, b, c, d, e, f, g, w, 49, 0x1e376c08);
    rnd!(g, h, a, b, c, d, e, f, w, 50, 0x2748774c);
    rnd!(f, g, h, a, b, c, d, e, w, 51, 0x34b0bcb5);
    rnd!(e, f, g, h, a, b, c, d, w, 52, 0x391c0cb3);
    rnd!(d, e, f, g, h, a, b, c, w, 53, 0x4ed8aa4a);
    rnd!(c, d, e, f, g, h, a, b, w, 54, 0x5b9cca4f);
    rnd!(b, c, d, e, f, g, h, a, w, 55, 0x682e6ff3);
    rnd!(a, b, c, d, e, f, g, h, w, 56, 0x748f82ee);
    rnd!(h, a, b, c, d, e, f, g, w, 57, 0x78a5636f);
    rnd!(g, h, a, b, c, d, e, f, w, 58, 0x84c87814);
    rnd!(f, g, h, a, b, c, d, e, w, 59, 0x8cc70208);
    rnd!(e, f, g, h, a, b, c, d, w, 60, 0x90befffa);
    rnd!(d, e, f, g, h, a, b, c, w, 61, 0xa4506ceb);
    rnd!(c, d, e, f, g, h, a, b, w, 62, 0xbef9a3f7);
    rnd!(b, c, d, e, f, g, h, a, w, 63, 0xc67178f2);

    s[0] = a.wrapping_add(s[0]);
    s[1] = b.wrapping_add(s[1]);
    s[2] = c.wrapping_add(s[2]);
    s[3] = d.wrapping_add(s[3]);
    s[4] = e.wrapping_add(s[4]);
    s[5] = f.wrapping_add(s[5]);
    s[6] = g.wrapping_add(s[6]);
    s[7] = h.wrapping_add(s[7]);
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    // CH(x, y, z) = (x AND y) XOR ((NOT x) AND z)
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    // MAJ(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn sigma0(x: u32) -> u32 {
    // ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn sigma1(x: u32) -> u32 {
    // ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn gamma0(x: u32) -> u32 {
    // ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
    x.rotate_right(7) ^ x.rotate_right(18) ^ x >> 3
}

#[inline(always)]
fn gamma1(x: u32) -> u32 {
    // ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
    x.rotate_right(17) ^ x.rotate_right(19) ^ x >> 10
}

const S_SHA256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::bytes_to_lower_hex;
    use quickcheck::{Gen, QuickCheck};
    use rust_crypto_sha2::Digest;

    #[test]
    fn test_sha256_examples() {
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        let data = [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];

        let mut sha256 = Sha256::new();
        for (message, digest_hex) in data {
            let digest = sha256.digest(message);
            assert_eq!(bytes_to_lower_hex(&digest), digest_hex);
        }
    }

    #[test]
    fn test_sha256_message_padding_against_another_implementation() {
        let total_bits = 2048;
        let mut bytes = Vec::new();
        let mut sha256 = Sha256::new();
        for _ in 0..total_bits / u8::BITS as usize {
            bytes.push(u8::MAX);
            let digest = sha256.digest(&bytes);

            let mut hasher = rust_crypto_sha2::Sha256::new();
            hasher.update(&bytes);
            let digest2 = hasher.finalize();

            assert_eq!(bytes_to_lower_hex(&digest), bytes_to_lower_hex(&digest2))
        }
    }

    #[test]
    fn test_sha256_against_another_implementation() {
        const TEST_NUMBER: u64 = 2000;
        const GEN_SIZE: usize = 1024 * 10;

        fn prop(bytes: Vec<u8>) -> bool {
            let digest = Sha256::new().digest(&bytes);

            let mut hasher = rust_crypto_sha2::Sha256::new();
            hasher.update(&bytes);
            let digest2 = hasher.finalize();

            bytes_to_lower_hex(&digest) == bytes_to_lower_hex(&digest2)
        }

        QuickCheck::new()
            .gen(Gen::new(GEN_SIZE))
            .tests(TEST_NUMBER)
            .quickcheck(prop as fn(bytes: Vec<u8>) -> bool)
    }
}
