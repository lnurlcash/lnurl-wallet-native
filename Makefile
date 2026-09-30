.PHONY: all build run dev test e2e reference-mint lint format clean

all: lint test

# optimized binary at target/release/lnurl-wallet-native
build:
	cargo build --release --locked

run: build
	./target/release/lnurl-wallet-native

# unoptimized, faster to compile
dev:
	cargo run

test:
	cargo test --locked

# end-to-end against a running reference mint (see `make reference-mint`)
LNURL_MINT_URL ?= http://127.0.0.1:8977
e2e:
	LNURL_MINT_URL=$(LNURL_MINT_URL) cargo test --locked reference_mint -- --ignored --test-threads=1

# lnurl-mint's real server over its test suite's fake Lightning node;
# needs a checkout at LNURL_MINT_DIR and uv
LNURL_MINT_DIR ?= ../lnurl-mint
reference-mint:
	cd $(LNURL_MINT_DIR) && LNURL_MINT_DIR=. uv run python $(CURDIR)/dev/reference-mint.py 8977

lint:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings

format:
	cargo fmt

clean:
	cargo clean
