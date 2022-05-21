// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Implements HMAC (NIST’s FIPS 198-1 standard and RFC 2104)
use crate::crypto::hash::core::UnkeyedHash;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::iter::zip;

pub fn hmac<T: AsRef<[u8]>, S: AsRef<[u8]>, H: UnkeyedHash>(
    key: T,
    message: S,
    hasher: &mut H,
) -> Vec<u8> {
    let key = key.as_ref();
    let message = message.as_ref();

    // debug_assert!(
    //     key.len() >= H::DIGEST_OUTPUT_BYTE_LENGTH,
    //     "key length less than L bytes is strongly discouraged"
    // );

    // Obtains `k0` from `key` (step 1, step 2, and step 3)
    let k0: Cow<[u8]> = {
        match key.len().cmp(&H::INPUT_BLOCK_BYTE_LENGTH) {
            Ordering::Less => {
                let mut t = key.to_vec();
                t.extend(vec![0; H::INPUT_BLOCK_BYTE_LENGTH - key.len()]);
                t.into()
            }
            Ordering::Equal => key.into(),
            Ordering::Greater => hasher.digest(key).into(),
        }
    };

    let mut t = Vec::with_capacity(k0.len() + message.len());
    // Step 4: `k0` XOR `ipad`
    t.extend_from_slice(&vec![0x36; H::INPUT_BLOCK_BYTE_LENGTH]);
    for (k0_element, t_element) in zip(k0.as_ref(), t.iter_mut()) {
        *t_element ^= k0_element;
    }

    // Step 5: appends `message` to the result from step 4
    // `k0` XOR `ipad` || `message`
    t.extend_from_slice(message);

    // Step 6: applies H to the result from step 5
    // H(`k0` XOR `ipad` || `message`)
    let step_6_result = hasher.digest(&t);

    // Step 7: `k0` XOR `opad`
    t.clear();
    t.extend_from_slice(&vec![0x5c; H::INPUT_BLOCK_BYTE_LENGTH]);
    for (k0_element, t_element) in zip(k0.as_ref(), t.iter_mut()) {
        *t_element ^= k0_element;
    }

    // Step 8: appends the result from step 6 to step 7
    // `k0` XOR `opad` || H(`k0` XOR `ipad` || `message`)
    t.extend_from_slice(&step_6_result);

    // Step 9: applies H to the result from step 8
    // H(`k0` XOR `opad` || H(`k0` XOR `ipad` || `message`))
    hasher.digest(&t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::codecs::{bytes_to_hex, hex_to_bytes};
    use crate::crypto::hash::{Sha256, Sha384, Sha512};

    #[test]
    fn test_hmac_examples() {
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA256.pdf
        // (key_hex, message, mac_hex)
        let data = [
            (
                concat!(
                    "000102030405060708090A0B0C0D0E0F",
                    "101112131415161718191A1B1C1D1E1F2021222324252627",
                    "28292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
                ),
                "Sample message for keylen=blocklen",
                "8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62",
            ),
            (
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "Sample message for keylen<blocklen",
                "a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790",
            ),
            (
                concat!(
                    "00010203",
                    "0405060708090A0B0C0D0E0F101112131415161718191A1B",
                    "1C1D1E1F202122232425262728292A2B2C2D2E2F30313233",
                    "3435363738393A3B3C3D3E3F404142434445464748494A4B",
                    "4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
                ),
                "Sample message for keylen=blocklen",
                "bdccb6c72ddeadb500ae768386cb38cc41c63dbb0878ddb9c7a38a431b78378d",
            ),
            (
                concat!(
                    "00",
                    "0102030405060708090A0B0C0D0E0F101112131415161718",
                    "191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"
                ),
                "Sample message for keylen<blocklen, with truncated tag",
                "27a8b157839efeac98df070b331d593618ddb985d403c0c786d23b5d132e57c7",
            ),
        ];
        let mut hasher = Sha256::new();
        for (key_hex, message, mac_hex) in data {
            let key = hex_to_bytes(key_hex).unwrap();
            let result = hmac(key, message, &mut hasher);
            assert_eq!(bytes_to_hex(&result), mac_hex);
        }

        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA384.pdf
        // (key_hex, message, mac_hex)
        let data = [
            (
                concat!(
                    "0001020304050607",
                    "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                    "202122232425262728292A2B2C2D2E2F3031323334353637",
                    "38393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
                    "505152535455565758595A5B5C5D5E5F6061626364656667",
                    "68696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
                ),
                "Sample message for keylen=blocklen",
                concat!(
                    "63c5daa5e651847ca897c95814ab830bededc7d25e83eef9",
                    "195cd45857a37f448947858f5af50cc2b1b730ddf29671a9"
                ),
            ),
            (
                concat!(
                    "000102030405060708090A0B0C0D0E0F1011121314151617",
                    "18191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"
                ),
                "Sample message for keylen<blocklen",
                concat!(
                    "6eb242bdbb582ca17bebfa481b1e23211464d2b7f8c20b9f",
                    "f2201637b93646af5ae9ac316e98db45d9cae773675eeed0"
                ),
            ),
            (
                concat!(
                    "0001020304050607",
                    "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                    "202122232425262728292A2B2C2D2E2F3031323334353637",
                    "38393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
                    "505152535455565758595A5B5C5D5E5F6061626364656667",
                    "68696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
                    "808182838485868788898A8B8C8D8E8F9091929394959697",
                    "98999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF",
                    "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7"
                ),
                "Sample message for keylen=blocklen",
                concat!(
                    "5b664436df69b0ca22551231a3f0a3d5b4f97991713cfa84",
                    "bff4d0792eff96c27dccbbb6f79b65d548b40e8564cef594"
                ),
            ),
            (
                concat!(
                    "00",
                    "0102030405060708090A0B0C0D0E0F101112131415161718",
                    "191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"
                ),
                "Sample message for keylen<blocklen, with truncated tag",
                concat!(
                    "c48130d3df703dd7cdaa56800dfbd2ba2458320e6e1f98fe",
                    "c8ad9f57f43800df3615ceb19ab648e1ecdd8c730af95c8a"
                ),
            ),
        ];
        let mut hasher = Sha384::new();
        for (key_hex, message, mac_hex) in data {
            let key = hex_to_bytes(key_hex).unwrap();
            let result = hmac(key, message, &mut hasher);
            assert_eq!(bytes_to_hex(&result), mac_hex);
        }

        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA512.pdf
        // (key_hex, message, mac_hex)
        let data = [
            (
                concat!(
                    "0001020304050607",
                    "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                    "202122232425262728292A2B2C2D2E2F3031323334353637",
                    "38393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
                    "505152535455565758595A5B5C5D5E5F6061626364656667",
                    "68696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
                ),
                "Sample message for keylen=blocklen",
                concat!(
                    "fc25e240658ca785b7a811a8d3f7b4ca",
                    "48cfa26a8a366bf2cd1f836b05fcb024bd36853081811d6c",
                    "ea4216ebad79da1cfcb95ea4586b8a0ce356596a55fb1347"
                ),
            ),
            (
                concat!(
                    "000102030405060708090A0B0C0D0E0F",
                    "101112131415161718191A1B1C1D1E1F2021222324252627",
                    "28292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
                ),
                "Sample message for keylen<blocklen",
                concat!(
                    "fd44c18bda0bb0a6ce0e82b031bf2818",
                    "f6539bd56ec00bdc10a8a2d730b3634de2545d639b0f2cf7",
                    "10d0692c72a1896f1f211c2b922d1a96c392e07e7ea9fedc"
                ),
            ),
            (
                concat!(
                    "0001020304050607",
                    "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                    "202122232425262728292A2B2C2D2E2F3031323334353637",
                    "38393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
                    "505152535455565758595A5B5C5D5E5F6061626364656667",
                    "68696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
                    "808182838485868788898A8B8C8D8E8F9091929394959697",
                    "98999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF",
                    "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
                ),
                "Sample message for keylen=blocklen",
                concat!(
                    "d93ec8d2de1ad2a9957cb9b83f14e76a",
                    "d6b5e0cce285079a127d3b14bccb7aa7286d4ac0d4ce6421",
                    "5f2bc9e6870b33d97438be4aaa20cda5c5a912b48b8e27f3"
                ),
            ),
            (
                concat!(
                    "00",
                    "0102030405060708090A0B0C0D0E0F101112131415161718",
                    "191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"
                ),
                "Sample message for keylen<blocklen, with truncated tag",
                concat!(
                    "00f3e9a77bb0f06de15f160603e42b50",
                    "28758808596664c03e1ab8fb2b0767780563aedc644960d4",
                    "f0c0c5d239f67a2a61b141e8c871f3d40db2c605588dab92"
                ),
            ),
        ];
        let mut hasher = Sha512::new();
        for (key_hex, message, mac_hex) in data {
            let key = hex_to_bytes(key_hex).unwrap();
            let result = hmac(key, message, &mut hasher);
            assert_eq!(bytes_to_hex(&result), mac_hex);
        }
    }
}
