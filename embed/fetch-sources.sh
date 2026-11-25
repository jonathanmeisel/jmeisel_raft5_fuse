#!/bin/sh
# Fetches the sources the `convert` example reads, at pinned revisions,
# into the folder given (about 1.6 GB). Usage: embed/fetch-sources.sh <src>
set -eu
src=$1
e5=https://huggingface.co/intfloat/multilingual-e5-small/resolve/614241f622f53c4eeff9890bdc4f31cfecc418b3
mclip=https://huggingface.co/sentence-transformers/clip-ViT-B-32-multilingual-v1/resolve/58edf8cada9e398793dca955574a48cbb7f18be2
clip=https://huggingface.co/sentence-transformers/clip-ViT-B-32/resolve/327ab6726d33c0e22f920c83f2ff9e4bd38ca37f
mkdir -p "$src/e5" "$src/mclip/2_Dense" "$src/clip"
for f in config.json tokenizer.json model.safetensors; do
    curl -sfL -o "$src/e5/$f" "$e5/$f"
    curl -sfL -o "$src/mclip/$f" "$mclip/$f"
done
curl -sfL -o "$src/mclip/2_Dense/model.safetensors" "$mclip/2_Dense/model.safetensors"
curl -sfL -o "$src/clip/config.json" "$clip/0_CLIPModel/config.json"
curl -sfL -o "$src/clip/model.safetensors" "$clip/0_CLIPModel/model.safetensors"
