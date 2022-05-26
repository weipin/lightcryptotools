// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_core::{BigInt, Sign};
use super::bytes::be_digits_to_be_bytes;
use crate::crypto::codecs::bytes_to_lower_hex;

impl BigInt {
    /// Returns the hexadecimal representation.
    ///
    /// The representation is "1-byte aligned", matching the behavior of the method `from_hex`.
    /// For instance, the hexadecimal representation of value zero is "00".
    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return "00".to_string();
        }

        let bytes = self.to_be_bytes();
        let mut hex = bytes_to_lower_hex(&bytes);

        match self.sign {
            Sign::Positive => hex,
            Sign::Negative => {
                hex.insert(0, '-');
                hex
            }
        }
    }

    /// Return the memory representation of this big integer as a byte array in big-endian byte order.
    pub(crate) fn to_be_bytes(&self) -> Vec<u8> {
        let mut digits = self.as_digits().to_vec();
        digits.reverse();

        be_digits_to_be_bytes(&digits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_hex() {
        let data = [
            (BigInt::from(0), "00"),
            (BigInt::from(1), "01"),
            (BigInt::from(-1), "-01"),
            (BigInt::from(i8::MIN), "-80"),
            (BigInt::from_hex("").unwrap(), "00"),
            (BigInt::from_hex("-00").unwrap(), "00"),
            (BigInt::from_hex("+00").unwrap(), "00"),
        ];

        for (a, output) in data {
            assert_eq!(a.to_hex(), output);
        }
    }
}
