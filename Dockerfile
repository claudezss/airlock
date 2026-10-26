# syntax=docker/dockerfile:1
# The relay image: a static airlox-server with the web UI (and its wasm core)
# embedded, on an empty base. Build: docker build -t airlox-server .

FROM rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS build
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Toolchain from rust-toolchain.toml (with the wasm target), the musl target
# for this machine, and a checksum-verified wasm-bindgen 0.2.100.
WORKDIR /src
COPY rust-toolchain.toml ./
RUN set -eux; \
    rustup show active-toolchain || rustup toolchain install; \
    arch="$(uname -m)"; \
    rustup target add "$arch-unknown-linux-musl"; \
    case "$arch" in \
      x86_64) wb=x86_64-unknown-linux-musl; sum=63d6a38deb65bd7023c02bdf382ab66b0d2c0241c8582fd3413b5a808b8aeb5b ;; \
      aarch64) wb=aarch64-unknown-linux-gnu; sum=52552984965fbd125efc6be052b3cb8872fb3c69559e4ec7775cbff64ed440cf ;; \
      *) echo "unsupported architecture $arch" >&2; exit 1 ;; \
    esac; \
    curl -sSfL -o /tmp/wb.tgz "https://github.com/rustwasm/wasm-bindgen/releases/download/0.2.100/wasm-bindgen-0.2.100-$wb.tar.gz"; \
    echo "$sum  /tmp/wb.tgz" | sha256sum -c -; \
    tar -xzf /tmp/wb.tgz -C /usr/local/bin --strip-components=1 "wasm-bindgen-0.2.100-$wb/wasm-bindgen"; \
    rm /tmp/wb.tgz

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    cargo build --locked --release -p airlox-core-wasm --target wasm32-unknown-unknown; \
    wasm-bindgen target/wasm32-unknown-unknown/release/airlox_core_wasm.wasm --out-dir /tmp/wasm --target web; \
    rm -rf web/pkg && mkdir -p web/pkg; \
    cp /tmp/wasm/airlox_core_wasm.js /tmp/wasm/airlox_core_wasm_bg.wasm web/pkg/; \
    target="$(uname -m)-unknown-linux-musl"; \
    cargo build --locked --release -p airlox-server --target "$target"; \
    mkdir -p /out/data; \
    cp "target/$target/release/airlox-server" /out/

FROM scratch
LABEL org.opencontainers.image.source=https://github.com/claudezss/airlox \
      org.opencontainers.image.description="Airlox relay" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=build /out/airlox-server /airlox-server
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV AIRLOX_LISTEN=0.0.0.0:8080 \
    AIRLOX_DATA=/data
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["/airlox-server"]
