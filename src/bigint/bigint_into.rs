// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::bigint_core::{BigInt, Sign};
use super::bytes::digits_to_bytes_be;
use crate::crypto::bytes_to_hex;

impl BigInt {
    /// Returns the hexadecimal representation.
    pub(crate) fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }

        // Reverses `digits`, for the hex representation is in big-endian order.
        let mut digits = self.as_digits().to_vec();
        digits.reverse();

        let bytes = digits_to_bytes_be(&digits);
        let mut hex = bytes_to_hex(&bytes);
        // Excludes leading zeros.
        let start = hex.chars().position(|c| c != '0').unwrap();
        let mut hex = hex.split_off(start);

        match self.sign {
            Sign::Positive => hex,
            Sign::Negative => {
                hex.insert(0, '-');
                hex
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_hex() {
        let data = [
            (BigInt::from(0), "0"),
            (BigInt::from(1), "1"),
            (BigInt::from(-1), "-1"),
            (BigInt::from(i8::MIN), "-80"),
            (BigInt::try_from("").unwrap(), "0"),
            (BigInt::try_from("-0").unwrap(), "0"),
            (BigInt::try_from("+0").unwrap(), "0"),
        ];

        for (a, output) in data {
            assert_eq!(a.to_hex(), output);
        }
    }
}
