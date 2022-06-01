// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

///! Implements SHA-384 and SHA-512
///
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
use super::core::calculate_k;
use super::core::rnd;
use crate::crypto::hash::core::UnkeyedHash;
use std::iter::zip;

pub struct Sha384 {
    // State
    s: [u64; 8],
    // Expanded message block
    w: [u64; 80],
}

impl Sha384 {
    pub fn new() -> Sha384 {
        Sha384 {
            s: [0; 8],
            w: [0; 80],
        }
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl UnkeyedHash for Sha384 {
    const INPUT_BLOCK_BYTE_LENGTH: usize = 128;
    const OUTPUT_BYTE_LENGTH: usize = 48;

    fn digest<T: AsRef<[u8]>>(&mut self, message: T) -> Vec<u8> {
        sha384_512_digest_core(message.as_ref(), &mut self.s, &mut self.w, &S_SHA384);

        let mut digest = Vec::with_capacity(std::mem::size_of::<u64>() * 6);
        for item in self.s.iter().take(6) {
            digest.extend(&item.to_be_bytes());
        }
        debug_assert_eq!(digest.len(), Self::OUTPUT_BYTE_LENGTH);

        digest
    }
}

pub struct Sha512 {
    // State
    s: [u64; 8],
    // Expanded message block
    w: [u64; 80],
}

impl Sha512 {
    pub fn new() -> Sha512 {
        Sha512 {
            s: [0; 8],
            w: [0; 80],
        }
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl UnkeyedHash for Sha512 {
    const INPUT_BLOCK_BYTE_LENGTH: usize = 128;
    const OUTPUT_BYTE_LENGTH: usize = 64;

    fn digest<T: AsRef<[u8]>>(&mut self, message: T) -> Vec<u8> {
        sha384_512_digest_core(message.as_ref(), &mut self.s, &mut self.w, &S_SHA512);

        let mut digest = Vec::with_capacity(std::mem::size_of::<u64>() * 8);
        for item in self.s {
            digest.extend(&item.to_be_bytes());
        }
        debug_assert_eq!(digest.len(), Self::OUTPUT_BYTE_LENGTH);

        digest
    }
}

#[allow(non_snake_case)]
fn sha384_512_digest_core(
    message: &[u8],
    s: &mut [u64; 8],
    w: &mut [u64; 80],
    s_init: &[u64; 8],
) {
    s.copy_from_slice(s_init);
    w.fill(0);

    let mut chunks = message.chunks_exact(Sha512::INPUT_BLOCK_BYTE_LENGTH);
    for block in chunks.by_ref() {
        sha512_block_compression(block, s, w);
    }

    let mut remaining = chunks.remainder().to_vec();
    // Pads the message
    // l: length of `message` in bits
    let l = u64::try_from(message.len()).unwrap() * 8;
    let k = calculate_k(l, Sha512::INPUT_BLOCK_BYTE_LENGTH as u64 * 8, 128);
    // Appends bit 1, 1-byte aligned
    remaining.push(0x80);
    // Appends zero bytes
    remaining.append(&mut vec![0; (k - 7) as usize / 8]);
    // Appends `l` in binary representation
    remaining.extend(&0_u64.to_be_bytes());
    remaining.extend(&l.to_be_bytes());
    debug_assert!(
        remaining.len() == Sha512::INPUT_BLOCK_BYTE_LENGTH
            || remaining.len() == Sha512::INPUT_BLOCK_BYTE_LENGTH * 2
    );

    for block in remaining.chunks_exact(Sha512::INPUT_BLOCK_BYTE_LENGTH) {
        sha512_block_compression(block, s, w);
    }
}

#[inline(always)]
fn sha512_block_compression(block: &[u8], s: &mut [u64; 8], w: &mut [u64; 80]) {
    // Loads the 128-byte message block into w[0..15] in big-endian order
    for (u64_bytes, w_iter) in zip(
        block.chunks_exact(std::mem::size_of::<u64>()),
        w[..16].iter_mut(),
    ) {
        *w_iter = u64::from_be_bytes(u64_bytes.try_into().unwrap());
    }

    // Expands the message block
    for i in 16..80 {
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
    // [1]: https://github.com/libtom/libtomcrypt/blob/7e7eb695d581782f04b24dc444cbfde86af59853/src/hashes/sha2/sha512.c#L130
    rnd!(a, b, c, d, e, f, g, h, w, 0, 0x428a2f98d728ae22);
    rnd!(h, a, b, c, d, e, f, g, w, 1, 0x7137449123ef65cd);
    rnd!(g, h, a, b, c, d, e, f, w, 2, 0xb5c0fbcfec4d3b2f);
    rnd!(f, g, h, a, b, c, d, e, w, 3, 0xe9b5dba58189dbbc);
    rnd!(e, f, g, h, a, b, c, d, w, 4, 0x3956c25bf348b538);
    rnd!(d, e, f, g, h, a, b, c, w, 5, 0x59f111f1b605d019);
    rnd!(c, d, e, f, g, h, a, b, w, 6, 0x923f82a4af194f9b);
    rnd!(b, c, d, e, f, g, h, a, w, 7, 0xab1c5ed5da6d8118);
    rnd!(a, b, c, d, e, f, g, h, w, 8, 0xd807aa98a3030242);
    rnd!(h, a, b, c, d, e, f, g, w, 9, 0x12835b0145706fbe);
    rnd!(g, h, a, b, c, d, e, f, w, 10, 0x243185be4ee4b28c);
    rnd!(f, g, h, a, b, c, d, e, w, 11, 0x550c7dc3d5ffb4e2);
    rnd!(e, f, g, h, a, b, c, d, w, 12, 0x72be5d74f27b896f);
    rnd!(d, e, f, g, h, a, b, c, w, 13, 0x80deb1fe3b1696b1);
    rnd!(c, d, e, f, g, h, a, b, w, 14, 0x9bdc06a725c71235);
    rnd!(b, c, d, e, f, g, h, a, w, 15, 0xc19bf174cf692694);
    rnd!(a, b, c, d, e, f, g, h, w, 16, 0xe49b69c19ef14ad2);
    rnd!(h, a, b, c, d, e, f, g, w, 17, 0xefbe4786384f25e3);
    rnd!(g, h, a, b, c, d, e, f, w, 18, 0x0fc19dc68b8cd5b5);
    rnd!(f, g, h, a, b, c, d, e, w, 19, 0x240ca1cc77ac9c65);
    rnd!(e, f, g, h, a, b, c, d, w, 20, 0x2de92c6f592b0275);
    rnd!(d, e, f, g, h, a, b, c, w, 21, 0x4a7484aa6ea6e483);
    rnd!(c, d, e, f, g, h, a, b, w, 22, 0x5cb0a9dcbd41fbd4);
    rnd!(b, c, d, e, f, g, h, a, w, 23, 0x76f988da831153b5);
    rnd!(a, b, c, d, e, f, g, h, w, 24, 0x983e5152ee66dfab);
    rnd!(h, a, b, c, d, e, f, g, w, 25, 0xa831c66d2db43210);
    rnd!(g, h, a, b, c, d, e, f, w, 26, 0xb00327c898fb213f);
    rnd!(f, g, h, a, b, c, d, e, w, 27, 0xbf597fc7beef0ee4);
    rnd!(e, f, g, h, a, b, c, d, w, 28, 0xc6e00bf33da88fc2);
    rnd!(d, e, f, g, h, a, b, c, w, 29, 0xd5a79147930aa725);
    rnd!(c, d, e, f, g, h, a, b, w, 30, 0x06ca6351e003826f);
    rnd!(b, c, d, e, f, g, h, a, w, 31, 0x142929670a0e6e70);
    rnd!(a, b, c, d, e, f, g, h, w, 32, 0x27b70a8546d22ffc);
    rnd!(h, a, b, c, d, e, f, g, w, 33, 0x2e1b21385c26c926);
    rnd!(g, h, a, b, c, d, e, f, w, 34, 0x4d2c6dfc5ac42aed);
    rnd!(f, g, h, a, b, c, d, e, w, 35, 0x53380d139d95b3df);
    rnd!(e, f, g, h, a, b, c, d, w, 36, 0x650a73548baf63de);
    rnd!(d, e, f, g, h, a, b, c, w, 37, 0x766a0abb3c77b2a8);
    rnd!(c, d, e, f, g, h, a, b, w, 38, 0x81c2c92e47edaee6);
    rnd!(b, c, d, e, f, g, h, a, w, 39, 0x92722c851482353b);
    rnd!(a, b, c, d, e, f, g, h, w, 40, 0xa2bfe8a14cf10364);
    rnd!(h, a, b, c, d, e, f, g, w, 41, 0xa81a664bbc423001);
    rnd!(g, h, a, b, c, d, e, f, w, 42, 0xc24b8b70d0f89791);
    rnd!(f, g, h, a, b, c, d, e, w, 43, 0xc76c51a30654be30);
    rnd!(e, f, g, h, a, b, c, d, w, 44, 0xd192e819d6ef5218);
    rnd!(d, e, f, g, h, a, b, c, w, 45, 0xd69906245565a910);
    rnd!(c, d, e, f, g, h, a, b, w, 46, 0xf40e35855771202a);
    rnd!(b, c, d, e, f, g, h, a, w, 47, 0x106aa07032bbd1b8);
    rnd!(a, b, c, d, e, f, g, h, w, 48, 0x19a4c116b8d2d0c8);
    rnd!(h, a, b, c, d, e, f, g, w, 49, 0x1e376c085141ab53);
    rnd!(g, h, a, b, c, d, e, f, w, 50, 0x2748774cdf8eeb99);
    rnd!(f, g, h, a, b, c, d, e, w, 51, 0x34b0bcb5e19b48a8);
    rnd!(e, f, g, h, a, b, c, d, w, 52, 0x391c0cb3c5c95a63);
    rnd!(d, e, f, g, h, a, b, c, w, 53, 0x4ed8aa4ae3418acb);
    rnd!(c, d, e, f, g, h, a, b, w, 54, 0x5b9cca4f7763e373);
    rnd!(b, c, d, e, f, g, h, a, w, 55, 0x682e6ff3d6b2b8a3);
    rnd!(a, b, c, d, e, f, g, h, w, 56, 0x748f82ee5defb2fc);
    rnd!(h, a, b, c, d, e, f, g, w, 57, 0x78a5636f43172f60);
    rnd!(g, h, a, b, c, d, e, f, w, 58, 0x84c87814a1f0ab72);
    rnd!(f, g, h, a, b, c, d, e, w, 59, 0x8cc702081a6439ec);
    rnd!(e, f, g, h, a, b, c, d, w, 60, 0x90befffa23631e28);
    rnd!(d, e, f, g, h, a, b, c, w, 61, 0xa4506cebde82bde9);
    rnd!(c, d, e, f, g, h, a, b, w, 62, 0xbef9a3f7b2c67915);
    rnd!(b, c, d, e, f, g, h, a, w, 63, 0xc67178f2e372532b);
    rnd!(a, b, c, d, e, f, g, h, w, 64, 0xca273eceea26619c);
    rnd!(h, a, b, c, d, e, f, g, w, 65, 0xd186b8c721c0c207);
    rnd!(g, h, a, b, c, d, e, f, w, 66, 0xeada7dd6cde0eb1e);
    rnd!(f, g, h, a, b, c, d, e, w, 67, 0xf57d4f7fee6ed178);
    rnd!(e, f, g, h, a, b, c, d, w, 68, 0x06f067aa72176fba);
    rnd!(d, e, f, g, h, a, b, c, w, 69, 0x0a637dc5a2c898a6);
    rnd!(c, d, e, f, g, h, a, b, w, 70, 0x113f9804bef90dae);
    rnd!(b, c, d, e, f, g, h, a, w, 71, 0x1b710b35131c471b);
    rnd!(a, b, c, d, e, f, g, h, w, 72, 0x28db77f523047d84);
    rnd!(h, a, b, c, d, e, f, g, w, 73, 0x32caab7b40c72493);
    rnd!(g, h, a, b, c, d, e, f, w, 74, 0x3c9ebe0a15c9bebc);
    rnd!(f, g, h, a, b, c, d, e, w, 75, 0x431d67c49c100d4c);
    rnd!(e, f, g, h, a, b, c, d, w, 76, 0x4cc5d4becb3e42b6);
    rnd!(d, e, f, g, h, a, b, c, w, 77, 0x597f299cfc657e2a);
    rnd!(c, d, e, f, g, h, a, b, w, 78, 0x5fcb6fab3ad6faec);
    rnd!(b, c, d, e, f, g, h, a, w, 79, 0x6c44198c4a475817);

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
fn ch(x: u64, y: u64, z: u64) -> u64 {
    // CH(x, y, z) = (x AND y) XOR ((NOT x) AND z)
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    // MAJ(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn sigma0(x: u64) -> u64 {
    // ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline(always)]
fn sigma1(x: u64) -> u64 {
    // ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline(always)]
fn gamma0(x: u64) -> u64 {
    // ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
    x.rotate_right(1) ^ x.rotate_right(8) ^ x >> 7
}

#[inline(always)]
fn gamma1(x: u64) -> u64 {
    // ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
    x.rotate_right(19) ^ x.rotate_right(61) ^ x >> 6
}

static S_SHA384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

static S_SHA512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::bytes_to_lower_hex;
    use quickcheck::{Gen, QuickCheck};
    use rust_crypto_sha2::Digest;

    #[test]
    fn test_sha384_examples() {
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
        let data = [
            (
                "",
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            ),
            (
                "abc",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
            ),
        ];

        let mut sha384 = Sha384::new();
        for (message, digest_hex) in data {
            let digest = sha384.digest(message);
            assert_eq!(bytes_to_lower_hex(&digest), digest_hex);
        }
    }

    #[test]
    fn test_sha384_message_padding_against_another_implementation() {
        let total_bits = 4096;
        let mut bytes = Vec::new();
        let mut sha384 = Sha384::new();
        for _ in 0..total_bits / u8::BITS as usize {
            bytes.push(u8::MAX);
            let digest = sha384.digest(&bytes);

            let mut hasher = rust_crypto_sha2::Sha384::new();
            hasher.update(&bytes);
            let digest2 = hasher.finalize();

            assert_eq!(bytes_to_lower_hex(&digest), bytes_to_lower_hex(&digest2))
        }
    }

    #[test]
    fn test_sha384_against_another_implementation() {
        const TEST_NUMBER: u64 = 2000;
        const GEN_SIZE: usize = 1024 * 10;

        fn prop(bytes: Vec<u8>) -> bool {
            let digest = Sha384::new().digest(&bytes);

            let mut hasher = rust_crypto_sha2::Sha384::new();
            hasher.update(&bytes);
            let digest2 = hasher.finalize();

            bytes_to_lower_hex(&digest) == bytes_to_lower_hex(&digest2)
        }

        QuickCheck::new()
            .gen(Gen::new(GEN_SIZE))
            .tests(TEST_NUMBER)
            .quickcheck(prop as fn(bytes: Vec<u8>) -> bool)
    }

    #[test]
    fn test_sha512_examples() {
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
        let data = [
            (
                "",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
            (
                "abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            ),
        ];

        let mut sha512 = Sha512::new();
        for (message, digest_hex) in data {
            let digest = sha512.digest(message);
            assert_eq!(bytes_to_lower_hex(&digest), digest_hex);
        }
    }

    #[test]
    fn test_sha512_message_padding_against_another_implementation() {
        let total_bits = 4096;
        let mut bytes = Vec::new();
        let mut sha512 = Sha512::new();
        for _ in 0..total_bits / u8::BITS as usize {
            bytes.push(u8::MAX);
            let digest = sha512.digest(&bytes);

            let mut hasher = rust_crypto_sha2::Sha512::new();
            hasher.update(&bytes);
            let digest2 = hasher.finalize();

            assert_eq!(bytes_to_lower_hex(&digest), bytes_to_lower_hex(&digest2))
        }
    }

    #[test]
    fn test_sha512_against_another_implementation() {
        const TEST_NUMBER: u64 = 2000;
        const GEN_SIZE: usize = 1024 * 10;

        fn prop(bytes: Vec<u8>) -> bool {
            let digest = Sha512::new().digest(&bytes);

            let mut hasher = rust_crypto_sha2::Sha512::new();
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
