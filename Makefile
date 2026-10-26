# Airlox developer tasks. Requires: rustup, uv, maturin, wasm-bindgen-cli 0.2.100, node 20+.
.PHONY: all check fmt lint test test-rust test-python test-sdk test-wasm vectors wasm python server runner web clean

all: check

check: fmt lint test

fmt:
	cargo fmt --all --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo clippy -p airlox-core-wasm --target wasm32-unknown-unknown -- -D warnings

test: test-rust test-python test-sdk test-wasm

test-rust:
	cargo test --workspace --exclude airlox-core-py

VENV := $(CURDIR)/.venv

python:
	[ -d $(VENV) ] || uv venv -q --python 3.12 $(VENV)
	VIRTUAL_ENV=$(VENV) uv pip install -q pytest httpx hatchling editables
	cd bindings/python && VIRTUAL_ENV=$(VENV) maturin develop -q --uv
	VIRTUAL_ENV=$(VENV) uv pip install -q --no-deps --no-build-isolation -e python/airlox

server:
	cargo build -q -p airlox-server

runner:
	cargo build -q -p airlox

test-python: python
	$(VENV)/bin/python -m pytest -q bindings/python/tests

# Execute-mode tests use the local sandbox (needs uv; on Linux, unprivileged
# user namespaces) and, when a Docker daemon is up, the docker backend.
test-sdk: python server runner
	$(VENV)/bin/python -m pytest -q python/airlox/tests

wasm:
	cd bindings/wasm && npm run -s build

# The web UI loads the wasm package from web/pkg.
web: wasm
	rm -rf web/pkg && mkdir -p web/pkg
	cp bindings/wasm/pkg/web/airlox_core_wasm.js bindings/wasm/pkg/web/airlox_core_wasm_bg.wasm web/pkg/

test-wasm: wasm
	cd bindings/wasm && npm test

# Regenerate vectors. Only for an intentional protocol version bump.
vectors:
	cargo run -q -p airlox-core --example gen_vectors > crates/airlox-core/vectors/v1.json

clean:
	cargo clean
	rm -rf $(VENV) bindings/python/.venv bindings/wasm/pkg web/pkg
