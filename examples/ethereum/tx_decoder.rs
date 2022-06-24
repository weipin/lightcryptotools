// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Decodes transaction RLP and prints the structure.
//!
//! - The CLI has only one parameter: the "signed tx" hex.
//! - For the "signed tx" hex parameter, the prefix '0x' is optional.
//! - The CLI should be able to "detect" the transaction type
//!   among EIP-1559, EIP-2930, EIP-155, and Legacy.
//!
//! # Examples
//!
//! ```
//! # Legacy
//! cargo run --example tx_decoder -- \
//! f889808609184e72a0008227109400000000\
//! 0000000000000000000000000000000080a4\
//! 7f7465737432000000000000000000000000\
//! 000000000000000000000000000000600057\
//! 1ba070bad1a10475d4b24e8227978077233c\
//! 3367a7642701db223465793e68d368b3a07e\
//! 3d131ef92c04eca4e48f1f5c0d2ea971f280\
//! 2d0e61ec21c8354b605ad286c0
//!
//! # EIP 155
//! cargo run --example tx_decoder -- \
//! f86c098504a817c800825208943535353535\
//! 353535353535353535353535353535880de0\
//! b6b3a76400008025a028ef61340bd939bc21\
//! 95fe537567866003e1a15d3c71ff63e15906\
//! 20aa636276a067cbe9d8997f761aecb70330\
//! 4b3800ccf555c9f3dc64214b297fb1966a3b6d83
//!
//! # EIP 2930
//! cargo run --example tx_decoder -- \
//! 01f87081900984765898be81bb94f933abf2\
//! 475062e0f3e7bde89da3f6c9e6963b6781d7\
//! 8a74a53d7a649760e78359c001a07796c9c6\
//! e8e07fd5b084b720679f0a77995ef6d3c61c\
//! d669f2a4f756e29838c1a00511904f04111b\
//! 7d90322aa9a74159d8ca44b8b852aa37fa6fa3996b851956bd
//!
//! # EIP 1559
//! cargo run --example tx_decoder -- \
//! 02f89f7b2a4282014382520894123456789a\
//! 123456789a123456789a123456789a820123\
//! 80f838f794123456789a123456789a123456\
//! 789a123456789ae1a00123456789abcdef01\
//! 23456789abcdef0123456789abcdef012345\
//! 6789abcdef80a02cd518c375dfd2231b9352\
//! e600a559cd1c7dd38ed46f4e470bde6723aa\
//! 85ab90a0432f760d25c8aa48ee9933b81821\
//! b37a7408b45a253f0639a7875fe64f49f0b6
//! ```

use lightcryptotools::blockchain::ethereum::rlp::decoder::RlpDecodingItem;
use lightcryptotools::blockchain::ethereum::rlp::decoding::RlpDataDecodingError;
use lightcryptotools::blockchain::ethereum::transaction::{
    TransactionEip155, TransactionEip1559, TransactionEip2930, TransactionLegacy,
};
use lightcryptotools::crypto::codecs::hex_to_bytes;
use lightcryptotools::tools::codable::decode;

fn main() {
    let tx_hex = std::env::args()
        .nth(1)
        .expect("Error: the parameter is missing");
    let tx_hex = tx_hex.strip_prefix("0x").unwrap_or(&tx_hex);

    let tx_data = match hex_to_bytes(tx_hex) {
        Ok(data) => data,
        Err(err) => {
            panic!("Invalid hex input: {err}");
        }
    };

    if tx_data.len() < 1 {
        panic!("Invalid transaction hex input")
    }

    let first_byte = *tx_data.first().unwrap();
    if first_byte == TransactionEip1559::transaction_type() {
        // Decodes EIP-1559
        let transaction: TransactionEip1559 = match decode(&tx_data[1..]) {
            Ok(value) => value,
            Err(err) => {
                panic!("Decoding failed: {err}");
            }
        };
        println!("{transaction}");
    } else if first_byte == TransactionEip2930::transaction_type() {
        // Decodes EIP-2930
        let transaction: TransactionEip2930 = match decode(&tx_data[1..]) {
            Ok(value) => value,
            Err(err) => {
                panic!("Decoding failed: {err}");
            }
        };
        println!("{transaction}");
    } else {
        // Falls back to legacy types
        match decode::<TransactionEip155, RlpDecodingItem>(&tx_data) {
            // Decodes as EIP-155 first.
            // Without decoding and examining the `v` field,
            // we cannot tell if a tx is EIP-155 or legacy.
            Ok(transaction) => {
                println!("{transaction}");
            }
            Err(RlpDataDecodingError::TransactionTypeMismatch) => {
                // If decoding an EIP-155 fails with the error `TransactionTypeMismatch`,
                // the tx is the legacy type.
                match decode::<TransactionLegacy, RlpDecodingItem>(&tx_data) {
                    Ok(transaction) => {
                        println!("{transaction}");
                    }
                    Err(err) => {
                        panic!("Decoding failed: {err}");
                    }
                };
            }
            Err(err) => {
                panic!("Decoding failed: {err}");
            }
        };
    }
}
