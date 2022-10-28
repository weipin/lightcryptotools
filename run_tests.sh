cargo fmt -- --check
cargo clippy -- -D warnings

cargo nextest run

# Runs doctests explicitly, for nextest currently doesn't support doctests
cargo test --doc

# Tests time-consuming cases
cargo test --release -- --ignored

# cargo +nightly careful test

# cargo clean
# cargo miri test

# cargo bench

# Tests bigint for u8_digit
RUSTFLAGS="--cfg u8_digit" cargo nextest run bigint

# Tests against a big-endian platform
cross test --target powerpc-unknown-linux-gnu --lib
RUSTFLAGS="--cfg u8_digit" cross test bigint --target powerpc-unknown-linux-gnu --lib

