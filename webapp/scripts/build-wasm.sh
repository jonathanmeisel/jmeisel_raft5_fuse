#!/bin/sh
# Builds the client for browsers (the raft5fs-web crate), and the modules
# the embed Worker loads apart from it: the PDF reader (raft5fs-pdf-web)
# and the search models (raft5fs-embed-web), into src/wasm, which is
# generated and not committed. The wasm-bindgen CLI must be the version
# web/Cargo.toml pins: cargo install wasm-bindgen-cli --version <it>.
#
# The models' module is built with WebAssembly SIMD: candle picks its fast
# kernels when it is compiled, and every current browser has SIMD.
set -eu
cd "$(dirname "$0")/../.."
bindgen=${WASM_BINDGEN:-wasm-bindgen}
command -v "$bindgen" >/dev/null || bindgen="$HOME/.cargo/bin/wasm-bindgen"
cargo build -p raft5fs-web -p raft5fs-pdf-web --target wasm32-unknown-unknown --profile web
# RUSTFLAGS replaces .cargo/config.toml's flags, so it repeats them.
RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+simd128' \
    cargo build -p raft5fs-embed-web --target wasm32-unknown-unknown --profile web-models
for crate in raft5fs_web raft5fs_pdf_web; do
    "$bindgen" --target web --out-dir webapp/src/wasm \
        "target/wasm32-unknown-unknown/web/$crate.wasm"
done
"$bindgen" --target web --out-dir webapp/src/wasm \
    target/wasm32-unknown-unknown/web-models/raft5fs_embed_web.wasm
