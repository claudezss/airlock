# Airlock developer tasks. Requires: rustup, uv, maturin, wasm-bindgen-cli 0.2.100, node 20+.
.PHONY: all check fmt lint test test-rust test-python test-wasm vectors wasm python clean

all: check

check: fmt lint test

fmt:
	cargo fmt --all --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo clippy -p airlock-core-wasm --target wasm32-unknown-unknown -- -D warnings

test: test-rust test-python test-wasm

test-rust:
	cargo test --workspace --exclude airlock-core-py

python:
	cd bindings/python && [ -d .venv ] || uv venv -q --python 3.12 .venv
	cd bindings/python && VIRTUAL_ENV=$$PWD/.venv uv pip install -q pytest
	cd bindings/python && VIRTUAL_ENV=$$PWD/.venv maturin develop -q --uv

test-python: python
	cd bindings/python && .venv/bin/python -m pytest -q tests

wasm:
	cd bindings/wasm && npm run -s build

test-wasm: wasm
	cd bindings/wasm && npm test

# Regenerate vectors. Only for an intentional protocol version bump.
vectors:
	cargo run -q -p airlock-core --example gen_vectors > crates/airlock-core/vectors/v1.json

clean:
	cargo clean
	rm -rf bindings/python/.venv bindings/wasm/pkg
