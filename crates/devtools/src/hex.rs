// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use num_bigint::BigUint;

pub fn decimal_to_hex(decimal: &str) -> String {
    let a = BigUint::parse_bytes(decimal.as_bytes(), 10).unwrap();
    format!("{:x}", a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decimal_to_hex() {
        let decimal = "53093026025011841560144140884953714701527835907384159075569471996245155392944";
        let hex = "7561967ae7e35552012b5778030b36a39b62dfe899bb9edbbc57344e94f22db0";

        assert_eq!(decimal_to_hex(decimal), hex);
    }
}
