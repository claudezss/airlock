# Airlock developer tasks. Requires: rustup, uv, maturin, wasm-bindgen-cli 0.2.100, node 20+.
.PHONY: all check fmt lint test test-rust test-python test-sdk test-wasm vectors wasm python server web clean

all: check

check: fmt lint test

fmt:
	cargo fmt --all --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo clippy -p airlock-core-wasm --target wasm32-unknown-unknown -- -D warnings

test: test-rust test-python test-sdk test-wasm

test-rust:
	cargo test --workspace --exclude airlock-core-py

VENV := $(CURDIR)/.venv

python:
	[ -d $(VENV) ] || uv venv -q --python 3.12 $(VENV)
	VIRTUAL_ENV=$(VENV) uv pip install -q pytest httpx hatchling editables
	cd bindings/python && VIRTUAL_ENV=$(VENV) maturin develop -q --uv
	VIRTUAL_ENV=$(VENV) uv pip install -q --no-deps --no-build-isolation -e python/airlock-agent

server:
	cargo build -q -p airlock-server

test-python: python
	$(VENV)/bin/python -m pytest -q bindings/python/tests

test-sdk: python server
	$(VENV)/bin/python -m pytest -q python/airlock-agent/tests

wasm:
	cd bindings/wasm && npm run -s build

# The web UI loads the wasm package from web/pkg.
web: wasm
	rm -rf web/pkg && mkdir -p web/pkg
	cp bindings/wasm/pkg/web/airlock_core_wasm.js bindings/wasm/pkg/web/airlock_core_wasm_bg.wasm web/pkg/

test-wasm: wasm
	cd bindings/wasm && npm test

# Regenerate vectors. Only for an intentional protocol version bump.
vectors:
	cargo run -q -p airlock-core --example gen_vectors > crates/airlock-core/vectors/v1.json

clean:
	cargo clean
	rm -rf $(VENV) bindings/python/.venv bindings/wasm/pkg web/pkg
