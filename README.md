# lightcryptotools

Intends to provide fundamental functions for crypto(currency) wallets.

# Constant time

All core algorithms aren't yet constant time. The [hex/bytes conversion](https://github.com/weipin/lightcryptotools/blob/main/src/crypto/codecs.rs),
a constant time port, is an exception.

There is an intention to add constant time support.
We have to note that when all core algorithms are constant time, it's still possible for a running problem to leak secrets, often
caused by compiler optimizations or shared hardware resources.

# Readability and zero dependency

TODO

# Functionality

## Secret
- Random bytes generation: [os rand](https://github.com/weipin/lightcryptotools/tree/main/src/random), [sample: randombytes](https://github.com/weipin/lightcryptotools/blob/main/examples/randombytes.rs)

## Crypto
- hash: [SHA2](https://github.com/weipin/lightcryptotools/tree/main/src/crypto/hash/sha2), [SHA3](https://github.com/weipin/lightcryptotools/tree/main/src/crypto/hash/sha3), [HMAC](https://github.com/weipin/lightcryptotools/blob/main/src/crypto/hash/hmac.rs)
- ECDSA: [ECDSA](https://github.com/weipin/lightcryptotools/tree/main/src/crypto/ecdsa), [passes Project Wycheproof](https://github.com/weipin/lightcryptotools/blob/main/tests/crypto/ecdsa_verifying_wycheproof.rs), [recovery](https://github.com/weipin/lightcryptotools/blob/main/src/crypto/ecdsa/ecdsa_public_key_recovery.rs)

## Ethereum
- EOA: [address construction](https://github.com/weipin/lightcryptotools/blob/main/src/blockchain/ethereum/account/eoa.rs), [sample1: eoa_key_to_address](https://github.com/weipin/lightcryptotools/blob/main/examples/ethereum/eoa_key_to_address.rs), [sample2: eoa_gen_vanity_address](https://github.com/weipin/lightcryptotools/blob/main/examples/ethereum/eoa_gen_vanity_address.rs)
- RLP: [encoding/decoding](https://github.com/weipin/lightcryptotools/tree/main/src/blockchain/ethereum/rlp), [sample: rlp_decoder](https://github.com/weipin/lightcryptotools/blob/main/examples/ethereum/rlp_decoder.rs)
- Transaction: [encoding/decoding](https://github.com/weipin/lightcryptotools/tree/main/src/blockchain/ethereum/transaction), [sample: tx_decoder](https://github.com/weipin/lightcryptotools/blob/main/examples/ethereum/tx_decoder.rs)

