// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::core::sha3_digest;
use super::core::KeccakfState;
use crate::crypto::hash::sha3::core::KECCAK_DELIMITER_SUFFIX_SHA3;
use crate::crypto::hash::UnkeyedHash;

pub struct Sha3_224 {
    s: KeccakfState,
}

impl Sha3_224 {
    pub fn new() -> Sha3_224 {
        Sha3_224 { s: [0; 25] }
    }
}

impl Default for Sha3_224 {
    fn default() -> Self {
        Self::new()
    }
}

impl UnkeyedHash for Sha3_224 {
    // See FIPS PUB 202, "Table 3: Input block sizes for HMAC"
    // `200 - 2 * OUTPUT_BYTE_LENGTH`
    const INPUT_BLOCK_BYTE_LENGTH: usize = 144;

    // `224 / size_of::<u64>()`
    const OUTPUT_BYTE_LENGTH: usize = 28;

    fn digest<T: AsRef<[u8]>>(&mut self, message: T) -> Vec<u8> {
        let result = sha3_digest(
            message.as_ref(),
            &mut self.s,
            Self::OUTPUT_BYTE_LENGTH,
            KECCAK_DELIMITER_SUFFIX_SHA3,
        );
        debug_assert_eq!(result.len(), Self::OUTPUT_BYTE_LENGTH);
        result
    }
}
