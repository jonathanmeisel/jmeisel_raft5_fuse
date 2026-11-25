"""Checks converted model files against search/data/models.json.

usage: check-models.py <converted> <models.json> <assets>

The converter writes <converted>/text/<file> and <converted>/clip/<file>;
as release assets they are named text-<file> and clip-<file>. Every file
that models.json pins from a release must be among them, with the SHA-256
pinned. The assets are copied into <assets>, ready to upload.
"""

import hashlib
import json
import os
import shutil
import sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    converted, manifest, assets = sys.argv[1:4]
    os.makedirs(assets, exist_ok=True)
    made = {}
    for group in ("text", "clip"):
        for name in os.listdir(os.path.join(converted, group)):
            made[f"{group}-{name}"] = os.path.join(converted, group, name)
    models = json.load(open(manifest))["models"]
    bad = []
    for key, model in models.items():
        for f in model["files"]:
            if "/releases/download/" not in f["url"]:
                continue
            asset = f["url"].rsplit("/", 1)[1]
            path = made.get(asset)
            if path is None:
                bad.append(f"{key}: {asset} wasn't made")
                continue
            got = sha256(path)
            if got != f["sha256"] or os.path.getsize(path) != f["size"]:
                bad.append(f"{key}: {asset} is {got} ({os.path.getsize(path)} bytes), not the pinned {f['sha256']} ({f['size']})")
                continue
            shutil.copy(path, os.path.join(assets, asset))
            print(f"ok  {asset}  {got}")
    if bad:
        print("\n".join(bad), file=sys.stderr)
        sys.exit(1)


main()
