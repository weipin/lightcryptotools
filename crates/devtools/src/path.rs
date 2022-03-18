// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::path::PathBuf;

pub fn unit_testing_data_path(relative_path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(relative_path)
}

pub fn integration_testing_data_path(relative_path: &str) -> PathBuf {
    PathBuf::from("./")
        .join("tests/data")
        .join(relative_path)
}
