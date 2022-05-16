// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

///! Implements SHA-384 and SHA-512
///
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
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
    const MESSAGE_BLOCK_BYTE_LENGTH: usize = 128;
    const DIGEST_OUTPUT_BYTE_LENGTH: usize = 48;

    fn digest<T: AsRef<[u8]>>(&mut self, message: T) -> Vec<u8> {
        let (a, b, c, d, e, f, _, _) =
            sha384_512_digest_core(message.as_ref(), &mut self.s, &mut self.w, &S_SHA384);

        let mut digest = Vec::with_capacity(std::mem::size_of::<u64>() * 6);
        digest.extend_from_slice(&a.to_be_bytes());
        digest.extend_from_slice(&b.to_be_bytes());
        digest.extend_from_slice(&c.to_be_bytes());
        digest.extend_from_slice(&d.to_be_bytes());
        digest.extend_from_slice(&e.to_be_bytes());
        digest.extend_from_slice(&f.to_be_bytes());

        debug_assert_eq!(digest.len(), Self::DIGEST_OUTPUT_BYTE_LENGTH);
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
    const MESSAGE_BLOCK_BYTE_LENGTH: usize = 128;
    const DIGEST_OUTPUT_BYTE_LENGTH: usize = 64;

    fn digest<T: AsRef<[u8]>>(&mut self, message: T) -> Vec<u8> {
        let (a, b, c, d, e, f, g, h) =
            sha384_512_digest_core(message.as_ref(), &mut self.s, &mut self.w, &S_SHA512);

        let mut digest = Vec::with_capacity(std::mem::size_of::<u64>() * 8);
        digest.extend_from_slice(&a.to_be_bytes());
        digest.extend_from_slice(&b.to_be_bytes());
        digest.extend_from_slice(&c.to_be_bytes());
        digest.extend_from_slice(&d.to_be_bytes());
        digest.extend_from_slice(&e.to_be_bytes());
        digest.extend_from_slice(&f.to_be_bytes());
        digest.extend_from_slice(&g.to_be_bytes());
        digest.extend_from_slice(&h.to_be_bytes());

        debug_assert_eq!(digest.len(), Self::DIGEST_OUTPUT_BYTE_LENGTH);
        digest
    }
}

#[allow(non_snake_case)]
fn sha384_512_digest_core(
    message: &[u8],
    s: &mut [u64; 8],
    w: &mut [u64; 80],
    s_init: &[u64; 8],
) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    s.copy_from_slice(s_init);
    w.fill(0);

    let mut message = message.to_vec();
    let l = u64::try_from(message.len()).unwrap() * 8; // Length of `message` in bits

    // Message padding
    // a. Appends bit 1, 1-byte aligned
    message.push(0x80);

    // b. appends `k` bit 0 where `k` is the smallest, non-negative solution to the equation
    // (l + 1 + k) mod 1024 = 896,
    // (l + 1 + k + 128) mod 1024 = 0
    let k = {
        let t = 2048 - (l % 1024 + 1 + 128);
        if t >= 1024 {
            t - 1024
        } else {
            t
        }
    };
    let zero_paddings = vec![0; (k - 7) as usize / 8];
    message.extend_from_slice(&zero_paddings);

    // c. Appends `l` in binary representation
    message.extend_from_slice(&0_u64.to_be_bytes());
    message.extend_from_slice(&l.to_be_bytes());

    // Each block of message is 1024-bit, that is [u8;128]
    debug_assert!(message.len() % Sha512::MESSAGE_BLOCK_BYTE_LENGTH == 0);
    for block in message.chunks_exact(Sha512::MESSAGE_BLOCK_BYTE_LENGTH) {
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

        for i in 0..80 {
            let t1 = h
                .wrapping_add(sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        s[0] = a.wrapping_add(s[0]);
        s[1] = b.wrapping_add(s[1]);
        s[2] = c.wrapping_add(s[2]);
        s[3] = d.wrapping_add(s[3]);
        s[4] = e.wrapping_add(s[4]);
        s[5] = f.wrapping_add(s[5]);
        s[6] = g.wrapping_add(s[6]);
        s[7] = h.wrapping_add(s[7]);
    }

    (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])
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

#[rustfmt::skip]
static K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::bytes_to_hex;
    use ::quickcheck_macros::quickcheck;
    use ring::digest;

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
            assert_eq!(bytes_to_hex(&digest), digest_hex);
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

            let mut context = digest::Context::new(&digest::SHA384);
            context.update(&bytes);
            let digest2 = context.finish();

            assert_eq!(digest, digest2.as_ref())
        }
    }

    #[quickcheck]
    fn test_sha384_against_another_implementation(bytes: Vec<u8>) -> bool {
        let digest = Sha384::new().digest(&bytes);

        let mut context = digest::Context::new(&digest::SHA384);
        context.update(&bytes);
        let digest2 = context.finish();

        digest == digest2.as_ref()
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
            assert_eq!(bytes_to_hex(&digest), digest_hex);
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

            let mut context = digest::Context::new(&digest::SHA512);
            context.update(&bytes);
            let digest2 = context.finish();

            assert_eq!(digest, digest2.as_ref())
        }
    }

    #[quickcheck]
    fn test_sha512_against_another_implementation(bytes: Vec<u8>) -> bool {
        let digest = Sha512::new().digest(&bytes);

        let mut context = digest::Context::new(&digest::SHA512);
        context.update(&bytes);
        let digest2 = context.finish();

        digest == digest2.as_ref()
    }
}
