cargo fmt -- --check
cargo clippy -- -D warnings

cargo nextest run

# Tests time-consuming cases
cargo test --release -- --ignored

# cargo bench

# Tests bigint for u8_digit
RUSTFLAGS="--cfg u8_digit" cargo nextest run bigint

# Tests against a big-endian platform
cross test --target powerpc-unknown-linux-gnu --lib
RUSTFLAGS="--cfg u8_digit" cross test bigint --target powerpc-unknown-linux-gnu --lib

