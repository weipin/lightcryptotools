// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

///! Implements SHA-256
///
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
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
    const MESSAGE_BLOCK_BYTE_LENGTH: usize = 64;
    const DIGEST_OUTPUT_BYTE_LENGTH: usize = 32;

    fn digest<T: AsRef<[u8]>>(&mut self, message: T) -> Vec<u8> {
        let result = sha256_digest(message.as_ref(), &mut self.s, &mut self.w);
        debug_assert_eq!(result.len(), Self::DIGEST_OUTPUT_BYTE_LENGTH);
        result
    }
}

fn sha256_digest(message: &[u8], s: &mut [u32; 8], w: &mut [u32; 64]) -> Vec<u8> {
    s.copy_from_slice(&S_SHA256);
    w.fill(0);

    let mut message = message.to_vec();
    let l = u64::try_from(message.len()).unwrap() * 8; // Length of `message` in bits

    // Message padding
    // a. Appends bit 1, 1-byte aligned
    message.push(0x80);

    // b. appends `k` bit 0 where `k` is the smallest, non-negative solution to the equation
    // (l + 1 + k) mod 512 = 448,
    // (l + 1 + k + 64) mod 512 = 0
    let k = {
        let t = 1024 - (l % 512 + 1 + 64);
        if t >= 512 {
            t - 512
        } else {
            t
        }
    };
    let zero_paddings = vec![0; (k - 7) as usize / 8];
    message.extend_from_slice(&zero_paddings);

    // c. Appends `l` in binary representation
    message.extend_from_slice(&l.to_be_bytes());

    // Each block of message is 512-bit, that is [u8;64]
    debug_assert!(message.len() % Sha256::MESSAGE_BLOCK_BYTE_LENGTH == 0);
    for block in message.chunks_exact(Sha256::MESSAGE_BLOCK_BYTE_LENGTH) {
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

        for i in 0..64 {
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

    let mut digest = Vec::with_capacity(s.len() * std::mem::size_of::<u32>());
    for item in s {
        digest.extend_from_slice(&item.to_be_bytes());
    }
    digest
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

static S_SHA256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

// A fixed array used in the message compression step.
static K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::bytes_to_hex;
    use ::quickcheck_macros::quickcheck;
    use ring::digest;

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
            assert_eq!(bytes_to_hex(&digest), digest_hex);
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

            let mut context = digest::Context::new(&digest::SHA256);
            context.update(&bytes);
            let digest2 = context.finish();

            assert_eq!(digest, digest2.as_ref())
        }
    }

    #[quickcheck]
    fn test_sha256_against_another_implementation(bytes: Vec<u8>) -> bool {
        let digest = Sha256::new().digest(&bytes);

        let mut context = digest::Context::new(&digest::SHA256);
        context.update(&bytes);
        let digest2 = context.finish();

        digest == digest2.as_ref()
    }
}
