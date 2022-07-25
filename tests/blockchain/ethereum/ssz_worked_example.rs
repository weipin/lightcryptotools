//! Worked example: https://eth2book.info/altair/part2/building_blocks/ssz/#worked-example

use lightcryptotools::blockchain::ethereum::ssz::{
    SszDataDecodingError, SszDecodingItem, SszEncodingItem, SszType,
};
use lightcryptotools::crypto::codecs::{bytes_to_lower_hex, hex_to_bytes};
use lightcryptotools::tools::codable::{decode, encode, Decodable, DecodingItem, EncodingItem};

#[test]
fn test_indexed_attestation_encoding_and_decoding() {
    let value = IndexedAttestation {
        attesting_indices: vec![33652, 59750, 92360],
        data: AttestationData {
            slot: 3080829,
            index: 9,
            beacon_block_root: hex_to_bytes(
                "4f4250c05956f5c2b87129cf7372f14dd576fc152543bf7042e963196b843fe6",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            source: Checkpoint {
                epoch: 96274,
                root: hex_to_bytes(
                    "d24639f2e661bc1adcbe7157280776cf76670fff0fee0691f146ab827f4f1ade",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            },
            target: Checkpoint {
                epoch: 96275,
                root: hex_to_bytes(
                    "9bcd31881817ddeab686f878c8619d664e8bfa4f8948707cba5bc25c8d74915d",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            },
        },
        signature: hex_to_bytes(concat!(
            "aaf504503ff15ae86723c906b4b6bac91ad728e4431aea3be2e8e3acc888d8af",
            "5dffbbcf53b234ea8e3fde67fbb09120027335ec63cf23f0213cc439e8d1b856",
            "c2ddfc1a78ed3326fb9b4fe333af4ad3702159dbf9caeb1a4633b752991ac437"
        ))
        .unwrap()
        .try_into()
        .unwrap(),
    };
    let encoded_hex = concat!(
        "e40000007d022f000000000009000000000000004f4250c05956f5c2b87129cf7372f14dd576fc15",
        "2543bf7042e963196b843fe61278010000000000d24639f2e661bc1adcbe7157280776cf76670fff",
        "0fee0691f146ab827f4f1ade13780100000000009bcd31881817ddeab686f878c8619d664e8bfa4f",
        "8948707cba5bc25c8d74915daaf504503ff15ae86723c906b4b6bac91ad728e4431aea3be2e8e3ac",
        "c888d8af5dffbbcf53b234ea8e3fde67fbb09120027335ec63cf23f0213cc439e8d1b856c2ddfc1a",
        "78ed3326fb9b4fe333af4ad3702159dbf9caeb1a4633b752991ac437748300000000000066e90000",
        "00000000c868010000000000"
    );

    // Tests encoding
    assert_eq!(bytes_to_lower_hex(&encode(&value)), encoded_hex);

    // Tests decoding
    let decoded_value: IndexedAttestation =
        decode(&hex_to_bytes(encoded_hex).unwrap()).unwrap();
    assert_eq!(decoded_value, value);
}

#[derive(Debug, PartialEq, Eq)]
struct IndexedAttestation {
    attesting_indices: Vec<ValidatorIndex>,
    data: AttestationData,
    signature: BLSSignature,
}

impl SszType for IndexedAttestation {
    fn size() -> Option<u32> {
        None
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut encoding_item = SszEncodingItem::new();

        encoding_item.encode_as_container_element(&self.attesting_indices);
        encoding_item.encode_as_container_element(&self.data);
        encoding_item.encode_as_container_element(&self.signature);
        encoding_item.take_data()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
        let decoding_item = SszDecodingItem::new_from_data(bytes).unwrap();
        let sizes = [
            Vec::<ValidatorIndex>::size(),
            AttestationData::size(),
            BLSSignature::size(),
        ];
        let items = decoding_item.decode_as_items(&sizes)?;
        let mut iter = items.iter();

        let attesting_indices = Vec::<ValidatorIndex>::decode_from(iter.next().unwrap())?;
        let data = AttestationData::decode_from(iter.next().unwrap())?;
        let signature = BLSSignature::decode_from(iter.next().unwrap())?;
        Ok(IndexedAttestation {
            attesting_indices,
            data,
            signature,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AttestationData {
    slot: Slot,
    index: CommitteeIndex,
    beacon_block_root: Hash256,
    source: Checkpoint,
    target: Checkpoint,
}

impl SszType for AttestationData {
    fn size() -> Option<u32> {
        Some(
            Slot::size().unwrap()
                + CommitteeIndex::size().unwrap()
                + Hash256::size().unwrap()
                + Checkpoint::size().unwrap()
                + Checkpoint::size().unwrap(),
        )
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut encoding_item = SszEncodingItem::new();

        encoding_item.encode_as_container_element(&self.slot);
        encoding_item.encode_as_container_element(&self.index);
        encoding_item.encode_as_container_element(&self.beacon_block_root);
        encoding_item.encode_as_container_element(&self.source);
        encoding_item.encode_as_container_element(&self.target);
        encoding_item.take_data()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
        let decoding_item = SszDecodingItem::new_from_data(bytes).unwrap();
        let sizes = [
            Slot::size(),
            CommitteeIndex::size(),
            Hash256::size(),
            Checkpoint::size(),
            Checkpoint::size(),
        ];
        let items = decoding_item.decode_as_items(&sizes)?;
        let mut iter = items.iter();

        let slot = Slot::decode_from(iter.next().unwrap())?;
        let index = CommitteeIndex::decode_from(iter.next().unwrap())?;
        let beacon_block_root = Hash256::decode_from(iter.next().unwrap())?;
        let source = Checkpoint::decode_from(iter.next().unwrap())?;
        let target = Checkpoint::decode_from(iter.next().unwrap())?;

        Ok(AttestationData {
            slot,
            index,
            beacon_block_root,
            source,
            target,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Checkpoint {
    epoch: Epoch,
    root: Hash256,
}

impl SszType for Checkpoint {
    fn size() -> Option<u32> {
        Some(Epoch::size().unwrap() + Hash256::size().unwrap())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut encoding_item = SszEncodingItem::new();

        encoding_item.encode_as_container_element(&self.epoch);
        encoding_item.encode_as_container_element(&self.root);
        encoding_item.take_data()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, SszDataDecodingError> {
        let decoding_item = SszDecodingItem::new_from_data(bytes).unwrap();
        let sizes = [Epoch::size(), Hash256::size()];
        let items = decoding_item.decode_as_items(&sizes)?;
        let mut iter = items.iter();

        let epoch = Epoch::decode_from(iter.next().unwrap())?;
        let root = Hash256::decode_from(iter.next().unwrap())?;
        Ok(Checkpoint { epoch, root })
    }
}

type BLSSignature = [u8; 96];
type ValidatorIndex = u64;
type CommitteeIndex = u64;
type Epoch = u64;
type Slot = u64;
type Hash256 = [u8; 32];
