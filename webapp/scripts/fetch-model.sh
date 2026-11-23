#!/bin/sh
# Fetches the search model into public/models/<model>/, and copies the
# places table into public/data/, for the build to
# serve from the app's own origin (the page's CSP loads nothing from
# elsewhere). The same files, at the same revision, as native clients use
# (raft5fs-indexer's `embed`); each is checked against its SHA-256. The
# model is cut into pieces under 100 MB, the most GitHub Pages takes in a
# file; the embed Worker joins them and checks the whole again.
#
# Not committed (see .gitignore). Fetches nothing already there.
set -eu
cd "$(dirname "$0")/.."
model=multilingual-e5-small-int8@761b726
repo=https://huggingface.co/Xenova/multilingual-e5-small/resolve/761b726dd34fb83930e26aab4e9ac3899aa1fa78
out="public/models/$model"
mkdir -p "$out"

# A file is there only once its download checked out: it is renamed into
# place after the check.
fetch() { # <file in repo> <name here> <sha256>
    if [ -f "$out/$2" ]; then return; fi
    curl -fsSL -o "$out/$2.part" "$repo/$1"
    echo "$3  $out/$2.part" | sha256sum -c --quiet
    mv "$out/$2.part" "$out/$2"
}

fetch tokenizer.json tokenizer.json 0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39
fetch tokenizer_config.json tokenizer_config.json a1d6bc8734a6f635dc158508bef000f8e2e5a759c7d92f984b2c86e5ff53425b
if [ ! -f "$out/model.onnx.1" ]; then
    fetch onnx/model_quantized.onnx model.onnx f80102d3f2a1229f387d3c81909990d8945513e347b0eab049f7de3c6f98c193
    split -b 60000000 -d -a 1 "$out/model.onnx" "$out/model.onnx."
    rm "$out/model.onnx"
fi
# CLIP's text side, for searching photos by what they show: the same files,
# at the same revision, as native clients' (raft5fs-indexer's `clip`).
clip=mclip-vit-b32-int8@58edf8c+6b7c523
crepo=https://huggingface.co/sentence-transformers/clip-ViT-B-32-multilingual-v1/resolve/58edf8cada9e398793dca955574a48cbb7f18be2
out="public/models/$clip"
mkdir -p "$out"
repo=$crepo
fetch tokenizer.json tokenizer.json 5b4e1a8171c81dfd666ae40265b9530c6e0b3d53923fe8ac493dcc84229adf81
fetch tokenizer_config.json tokenizer_config.json 8f66d0ad85be46afc77e0bbf48312cff326ddb9e7290926df96a8228d69a814e
fetch 2_Dense/model.safetensors dense.safetensors d12568dc7300970a4d3dbb49068ad16cd89b99840b74b026f8e48071e9414f74
if [ ! -f "$out/text.onnx.2" ]; then
    fetch onnx/model_quint8_avx2.onnx text.onnx fbc8fbeaa5237d96bd1bf430057c70d34de8334a463e933a5faa305f6caeed9c
    split -b 60000000 -d -a 1 "$out/text.onnx" "$out/text.onnx."
    rm "$out/text.onnx"
fi
ls "$out"

# The places table that tracks and photos are named with (search/data,
# committed), served beside the model.
mkdir -p public/data
cp ../search/data/places.bin public/data/places.bin
ls public/data
