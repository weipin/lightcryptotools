use devtools::hex::random_hex;
use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::ecdsa::PrivateKey;
use lightcryptotools::crypto::secp256k1;
use test::Bencher;

#[bench]
fn public_key_from_private(bench: &mut Bencher) {
    let secp256k1 = secp256k1();

    let bytes_len = 32;
    let n = BigInt::from_hex(random_hex(bytes_len * 2).as_str()).unwrap();
    let private_key = PrivateKey::new(n, secp256k1).unwrap();

    bench.iter(|| {
        let _ = private_key.public_key();
    })
}
