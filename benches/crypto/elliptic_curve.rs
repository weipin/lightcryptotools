// use devtools::hex::random_hex;
// use lightcryptotools::bigint::BigInt;
// use lightcryptotools::crypto::secp256k1;
// use test::Bencher;
//
// #[bench]
// fn public_key_from_private(bench: &mut Bencher) {
//     let secp256k1 = secp256k1();
//
//     let BYTES_LEN = 32;
//     let n = BigInt::from_hex(random_hex(BYTES_LEN * 2).as_str()).unwrap();
//     let secp256k1_n =
//         BigInt::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
//             .unwrap();
//     let private_key = n % secp256k1_n;
//
//     bench.iter(|| {
//         let _ = secp256k1.public_key(&private_key);
//     })
// }
