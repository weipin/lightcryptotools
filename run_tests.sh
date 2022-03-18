cargo fmt -- --check
cargo clippy -- -D warnings

cargo nextest run
RUSTFLAGS="--cfg u8_digit" cargo nextest run

# Tests against a big-endian platform
cross test --target powerpc-unknown-linux-gnu --lib
RUSTFLAGS="--cfg u8_digit" cross test --target powerpc-unknown-linux-gnu --lib

