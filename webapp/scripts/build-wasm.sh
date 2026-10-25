#!/bin/sh
# Builds the client for browsers (the raft5fs-web crate) into src/wasm,
# which is generated and not committed. The wasm-bindgen CLI must be the
# version web/Cargo.toml pins: cargo install wasm-bindgen-cli --version <it>.
set -eu
cd "$(dirname "$0")/../.."
bindgen=${WASM_BINDGEN:-wasm-bindgen}
command -v "$bindgen" >/dev/null || bindgen="$HOME/.cargo/bin/wasm-bindgen"
cargo build -p raft5fs-web --target wasm32-unknown-unknown --profile web
"$bindgen" --target web --out-dir webapp/src/wasm \
    target/wasm32-unknown-unknown/web/raft5fs_web.wasm
