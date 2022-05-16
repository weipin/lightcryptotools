// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub trait UnkeyedHash {
    const MESSAGE_BLOCK_BYTE_LENGTH: usize;
    const DIGEST_OUTPUT_BYTE_LENGTH: usize;

    fn digest<T: AsRef<[u8]>>(&mut self, message: T) -> Vec<u8>;
}
