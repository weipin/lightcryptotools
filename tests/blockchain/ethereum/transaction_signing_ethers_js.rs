// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use devtools::hex::byte_aligned_hex;
use devtools::path::integration_testing_data_path;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::blockchain::ethereum::transaction::TransactionBuilder;
use lightcryptotools::blockchain::ethereum::types::{AccessList, AccessListItem, StorageKey};
use lightcryptotools::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
use lightcryptotools::crypto::ecdsa::{PrivateKey, SigningOptions};
use lightcryptotools::crypto::secp256k1;
use serde_json::Value;
use std::fs::File;
use std::num::IntErrorKind;

#[test]
#[ignore]
fn test_signing_transaction_legacy() {
    let path = integration_testing_data_path("blockchain/ethereum/ethers.js/transactions.json");
    let file = File::open(path).unwrap();
    let value_vec: Vec<Value> = serde_json::from_reader(file).unwrap();

    let mut count = 0;
    for value in value_vec {
        let d_hex = value["privateKey"].as_str().unwrap();
        let nonce_hex = value["nonce"].as_str();
        let gas_price_hex = value["gasPrice"].as_str();
        let gas_limit_hex = value["gasLimit"].as_str();
        let to_hex = value["to"].as_str();
        let value_hex = value["value"].as_str();
        let data_hex = value["data"].as_str();

        // Ignores cases missing fields
        if nonce_hex.is_none()
            || gas_price_hex.is_none()
            || gas_limit_hex.is_none()
            || to_hex.is_none()
            || value_hex.is_none()
            || data_hex.is_none()
        {
            continue;
        }

        let gas_limit = match u64::from_str_radix(&gas_limit_hex.unwrap()[2..], 16) {
            Ok(n) => n,
            Err(err) => {
                match err.kind() {
                    IntErrorKind::Empty => 0,
                    _ => {
                        continue;
                    } // Ignores u64 overflow, for gas_limit is not a big integer
                }
            }
        };

        let curve = secp256k1();
        let d = BigInt::from_hex(&d_hex[2..]).unwrap();
        let private_key = PrivateKey::new(d, curve).unwrap();

        let transaction = TransactionBuilder::new()
            .with_nonce(
                u64::from_str_radix(&nonce_hex.unwrap()[2..], 16)
                    .unwrap_or_default()
                    .try_into()
                    .unwrap(),
            )
            .with_gas_price(gas_price_hex.unwrap().try_into().unwrap())
            .with_gas_limit(gas_limit)
            .with_destination(to_hex.unwrap().try_into().unwrap())
            .with_amount(value_hex.unwrap().try_into().unwrap())
            .with_data(hex_to_bytes(&data_hex.unwrap()[2..]).unwrap())
            .take_and_build_payload_legacy()
            .unwrap()
            .take_and_sign_with_options(
                &private_key,
                &SigningOptions {
                    employ_extra_random_data: false,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(
            bytes_to_lower_hex(&transaction.encode()),
            value["signedTransaction"].as_str().unwrap()[2..]
        );

        count += 1;
    }

    assert!(count > 900);
}

#[test]
#[ignore]
fn test_signing_transaction_eip_155_with_chain_id_5() {
    const CHAIN_ID: u64 = 5;

    let path = integration_testing_data_path("blockchain/ethereum/ethers.js/transactions.json");
    let file = File::open(path).unwrap();
    let value_vec: Vec<Value> = serde_json::from_reader(file).unwrap();

    let mut count = 0;
    for value in value_vec {
        let d_hex = value["privateKey"].as_str().unwrap();
        let nonce_hex = value["nonce"].as_str();
        let gas_price_hex = value["gasPrice"].as_str();
        let gas_limit_hex = value["gasLimit"].as_str();
        let to_hex = value["to"].as_str();
        let value_hex = value["value"].as_str();
        let data_hex = value["data"].as_str();

        // Ignores cases missing fields
        if nonce_hex.is_none()
            || gas_price_hex.is_none()
            || gas_limit_hex.is_none()
            || to_hex.is_none()
            || value_hex.is_none()
            || data_hex.is_none()
        {
            continue;
        }

        let gas_limit = match u64::from_str_radix(&gas_limit_hex.unwrap()[2..], 16) {
            Ok(n) => n,
            Err(err) => {
                match err.kind() {
                    IntErrorKind::Empty => 0,
                    _ => {
                        continue;
                    } // Ignores u64 overflow, for gas_limit is not a big integer
                }
            }
        };

        let curve = secp256k1();
        let d = BigInt::from_hex(&d_hex[2..]).unwrap();
        let private_key = PrivateKey::new(d, curve).unwrap();

        let transaction = TransactionBuilder::new()
            .with_chain_id(CHAIN_ID.into())
            .with_nonce(
                u64::from_str_radix(&nonce_hex.unwrap()[2..], 16)
                    .unwrap_or_default()
                    .try_into()
                    .unwrap(),
            )
            .with_gas_price(gas_price_hex.unwrap().try_into().unwrap())
            .with_gas_limit(gas_limit)
            .with_destination(to_hex.unwrap().try_into().unwrap())
            .with_amount(value_hex.unwrap().try_into().unwrap())
            .with_data(hex_to_bytes(&data_hex.unwrap()[2..]).unwrap())
            .take_and_build_payload_eip_155()
            .unwrap()
            .take_and_sign_with_options(
                &private_key,
                &SigningOptions {
                    employ_extra_random_data: false,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(
            bytes_to_lower_hex(&transaction.encode()),
            value["signedTransactionChainId5"].as_str().unwrap()[2..]
        );

        count += 1;
    }

    assert!(count > 900);
}

#[test]
#[ignore]
fn test_signing_transaction_eip_2930() {
    let path =
        integration_testing_data_path("blockchain/ethereum/ethers.js/typed-transactions.json");
    let file = File::open(path).unwrap();
    let value_vec: Vec<Value> = serde_json::from_reader(file).unwrap();

    let mut count = 0;
    for value in value_vec {
        let tx_value = &value["tx"];
        let tx_type = tx_value["type"].as_u64().unwrap();
        if tx_type != 1 {
            continue;
        }

        let d_hex = value["key"].as_str().unwrap();
        let chain_id = tx_value["chainId"].as_u64();
        let nonce = tx_value["nonce"].as_u64();
        let gas_price_hex = tx_value["gasPrice"].as_str();
        let gas_limit_hex = tx_value["gasLimit"].as_str();
        let to_hex = tx_value["to"].as_str();
        let value_hex = tx_value["value"].as_str();
        let data_hex = tx_value["data"].as_str();

        // Ignores cases missing fields
        if chain_id.is_none()
            || nonce.is_none()
            || gas_price_hex.is_none()
            || gas_limit_hex.is_none()
            || to_hex.is_none()
            || value_hex.is_none()
            || data_hex.is_none()
        {
            continue;
        }

        let gas_limit = match u64::from_str_radix(&gas_limit_hex.unwrap()[2..], 16) {
            Ok(n) => n,
            Err(err) => {
                match err.kind() {
                    IntErrorKind::Empty => 0,
                    _ => {
                        continue;
                    } // Ignores u64 overflow, for gas_limit is not a big integer
                }
            }
        };

        let access_list = match tx_value["accessList"] {
            Value::Null => AccessList::default(),
            ref value => json_object_to_access_list(value),
        };

        let curve = secp256k1();
        let d = BigInt::from_hex(&d_hex[2..]).unwrap();
        let private_key = PrivateKey::new(d, curve).unwrap();

        let transaction = TransactionBuilder::new()
            .with_chain_id(chain_id.unwrap().into())
            .with_nonce(nonce.unwrap().try_into().unwrap())
            .with_gas_price(
                byte_aligned_hex(gas_price_hex.unwrap())
                    .as_ref()
                    .try_into()
                    .unwrap(),
            )
            .with_gas_limit(gas_limit)
            .with_destination(to_hex.unwrap().try_into().unwrap())
            .with_amount(value_hex.unwrap().try_into().unwrap())
            .with_data(hex_to_bytes(&data_hex.unwrap()[2..]).unwrap())
            .with_access_list(access_list)
            .take_and_build_payload_eip_2930()
            .unwrap()
            .take_and_sign_with_options(
                &private_key,
                &SigningOptions {
                    employ_extra_random_data: false,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(
            bytes_to_lower_hex(&transaction.encode()),
            value["signed"].as_str().unwrap()[2..]
        );

        count += 1;
    }

    assert!(count > 500);
}

#[test]
#[ignore]
fn test_signing_transaction_eip_1559() {
    let path =
        integration_testing_data_path("blockchain/ethereum/ethers.js/typed-transactions.json");
    let file = File::open(path).unwrap();
    let value_vec: Vec<Value> = serde_json::from_reader(file).unwrap();

    let mut count = 0;
    for value in value_vec {
        let tx_value = &value["tx"];
        let tx_type = tx_value["type"].as_u64().unwrap();
        if tx_type != 2 {
            continue;
        }

        let d_hex = value["key"].as_str().unwrap();
        let chain_id = tx_value["chainId"].as_u64();
        let nonce = tx_value["nonce"].as_u64();
        let max_priority_fee_per_gas_hex = tx_value["maxPriorityFeePerGas"].as_str();
        let max_fee_per_gas_hex = tx_value["maxFeePerGas"].as_str();
        let gas_limit_hex = tx_value["gasLimit"].as_str();
        let to_hex = tx_value["to"].as_str();
        let value_hex = tx_value["value"].as_str();
        let data_hex = tx_value["data"].as_str();

        // Ignores cases missing fields
        if chain_id.is_none()
            || nonce.is_none()
            || max_priority_fee_per_gas_hex.is_none()
            || max_fee_per_gas_hex.is_none()
            || gas_limit_hex.is_none()
            || to_hex.is_none()
            || value_hex.is_none()
            || data_hex.is_none()
        {
            continue;
        }

        let gas_limit = match u64::from_str_radix(&gas_limit_hex.unwrap()[2..], 16) {
            Ok(n) => n,
            Err(err) => {
                match err.kind() {
                    IntErrorKind::Empty => 0,
                    _ => {
                        continue;
                    } // Ignores u64 overflow, for gas_limit is not a big integer
                }
            }
        };

        let access_list = match tx_value["accessList"] {
            Value::Null => AccessList::default(),
            ref value => json_object_to_access_list(value),
        };

        let curve = secp256k1();
        let d = BigInt::from_hex(&d_hex[2..]).unwrap();
        let private_key = PrivateKey::new(d, curve).unwrap();

        let transaction = TransactionBuilder::new()
            .with_chain_id(chain_id.unwrap().into())
            .with_nonce(nonce.unwrap().try_into().unwrap())
            .with_max_priority_fee_per_gas(
                byte_aligned_hex(max_priority_fee_per_gas_hex.unwrap())
                    .as_ref()
                    .try_into()
                    .unwrap(),
            )
            .with_max_fee_per_gas(
                byte_aligned_hex(max_fee_per_gas_hex.unwrap())
                    .as_ref()
                    .try_into()
                    .unwrap(),
            )
            .with_gas_limit(gas_limit)
            .with_destination(to_hex.unwrap().try_into().unwrap())
            .with_amount(value_hex.unwrap().try_into().unwrap())
            .with_data(hex_to_bytes(&data_hex.unwrap()[2..]).unwrap())
            .with_access_list(access_list)
            .take_and_build_payload_eip_1559()
            .unwrap()
            .take_and_sign_with_options(
                &private_key,
                &SigningOptions {
                    employ_extra_random_data: false,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(
            bytes_to_lower_hex(&transaction.encode()),
            value["signed"].as_str().unwrap()[2..]
        );

        count += 1;
    }

    assert!(count > 500);
}

// "accessList": [
//  {
//   "address": "0x6c822ade5f1c54ca4e452d8dcb12d1a28027c7df",
//   "storageKeys": [
//    "0x0a174ee8ba96dd49d5f2e03f74f4b9c0f88f3ba66a2bca8149107e73648508af",
//    "0x5a2685b58e32f34f373d2a4dee303ab7e5b3ec2879b1636711fdc5ff851fe5c5"
//   ]
//  },
//
// => AccessList

fn json_object_to_access_list(value: &Value) -> AccessList {
    let value_vec = value.as_array().unwrap();
    AccessList(
        value_vec
            .iter()
            .map(json_object_to_access_list_item)
            .collect(),
    )
}

fn json_object_to_access_list_item(value: &Value) -> AccessListItem {
    let address_hex = value["address"].as_str().unwrap();
    let storage_key_hex_list = value["storageKeys"].as_array().unwrap();

    let address = address_hex.try_into().unwrap();
    let mut storage_keys: Vec<StorageKey> = Vec::with_capacity(storage_key_hex_list.len());
    for hex in storage_key_hex_list {
        let storage_key = hex.as_str().unwrap().try_into().unwrap();
        storage_keys.push(storage_key);
    }

    AccessListItem {
        address,
        storage_keys,
    }
}
