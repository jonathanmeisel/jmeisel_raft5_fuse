#!/usr/bin/env bash
# Builds every binary the servers need, statically linked (musl), into
# out/bin: raft5-server and the `raft` admin shell from the raft5 store's
# repository (RAFT5_REPO in cluster.conf), and raft5fs-server from this
# one. Static so they run on whatever distribution the VMs have,
# whatever glibc this machine has.
#
# Needs, once:
#   rustup target add x86_64-unknown-linux-musl
#   and musl-gcc (Arch: pacman -S musl; Debian/Ubuntu: apt install musl-tools)
. "$(dirname "$0")/lib.sh"

TARGET=x86_64-unknown-linux-musl
rustup target list --installed | grep -qx $TARGET ||
    die "the $TARGET target isn't installed: rustup target add $TARGET"
command -v musl-gcc >/dev/null ||
    die "musl-gcc isn't installed (Arch: musl; Debian/Ubuntu: musl-tools)"

raft5=$(cd "$DEPLOY" && cd "$RAFT5_REPO" && pwd) ||
    die "RAFT5_REPO ($RAFT5_REPO) isn't a directory"

export CC_x86_64_unknown_linux_musl=musl-gcc
(cd "$raft5" && cargo build --release --target $TARGET -p raft5-server -p raft5-client)
(cd "$REPO" && cargo build --release --target $TARGET -p raft5fs-server)

mkdir -p "$OUT/bin"
cp "$raft5/target/$TARGET/release/raft5-server" \
    "$raft5/target/$TARGET/release/raft" \
    "$REPO/target/$TARGET/release/raft5fs-server" \
    "$OUT/bin/"
echo "built into $OUT/bin:"
ls -l "$OUT/bin"
