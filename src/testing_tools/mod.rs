// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub(crate) mod cpu_endian;
pub(crate) mod ethereum;
pub(crate) mod quickcheck;

#[cfg(test)]
mod tests {
    use crate::testing_tools::cpu_endian::cpu_endian;

    #[test]
    fn dump_info() {
        let cpu_endian = cpu_endian();
        println!("CPU endian: {cpu_endian}")
    }
}
