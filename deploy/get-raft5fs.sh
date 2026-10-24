#!/bin/sh
# Installs the raft5fs client from a GitHub release, after checking it
# against the release's SHA256SUMS. It picks the binary for this machine:
# Linux x86_64, macOS on Apple Silicon, or Android under Termux.
#
#   get-raft5fs.sh [--dest DIR] [VERSION]
#
#   VERSION     a release tag, e.g. v0.1.0 (default: the newest release)
#   --dest DIR  where to install raft5fs (default: $RAFT5FS_BIN_DIR, or
#               $PREFIX/bin under Termux, or else ~/bin)
#
# It replaces the file in one step, so a raft5fs that is running keeps its
# old file until it restarts.
set -eu

repo=jonathanmeisel/jmeisel_raft5_fuse

die() {
    echo "get-raft5fs: $*" >&2
    exit 1
}

if [ -n "${TERMUX_VERSION:-}" ]; then
    dir=${RAFT5FS_BIN_DIR:-${PREFIX:?}/bin}
else
    dir=${RAFT5FS_BIN_DIR:-$HOME/bin}
fi
version=
while [ $# -gt 0 ]; do
    case $1 in
    --dest)
        [ $# -ge 2 ] || die "--dest needs a directory"
        dir=$2
        shift 2
        ;;
    -h | --help)
        sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    -*) die "unknown option $1" ;;
    *)
        version=$1
        shift
        ;;
    esac
done

if [ -n "$version" ]; then
    url=https://github.com/$repo/releases/download/$version
else
    url=https://github.com/$repo/releases/latest/download
fi

# Which binary this machine runs.
case "$(uname -s)/$(uname -m)" in
Linux/x86_64) file=raft5fs-linux-x86_64 ;;
Linux/aarch64)
    [ -n "${TERMUX_VERSION:-}" ] || [ -d /system/bin ] ||
        die "there is no Linux ARM64 build, only one for Android (Termux)"
    file=raft5fs-android-aarch64
    ;;
Darwin/arm64) file=raft5fs-macos-aarch64 ;;
*) die "there is no build for $(uname -s) $(uname -m)" ;;
esac

command -v curl >/dev/null || die "curl isn't installed"

# Download into a temporary directory, removed however this exits.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "downloading $file from $url"
curl -fsSL -o "$file" "$url/$file" || die "cannot download $url/$file"
curl -fsSL -o SHA256SUMS "$url/SHA256SUMS" || die "cannot download $url/SHA256SUMS"

# Check only the line for this binary.
grep " $file\$" SHA256SUMS >expected || die "$file isn't in the release's SHA256SUMS"
if command -v sha256sum >/dev/null; then
    sha256sum -c expected >/dev/null 2>&1 || die "$file doesn't match its checksum; not installing"
else
    shasum -a 256 -c expected >/dev/null 2>&1 || die "$file doesn't match its checksum; not installing"
fi
echo "checksum ok"

mkdir -p "$dir"
chmod 755 "$file"
mv -f "$file" "$dir/raft5fs.new"
mv -f "$dir/raft5fs.new" "$dir/raft5fs"

echo "installed $dir/raft5fs: $("$dir/raft5fs" --version)"
case ":$PATH:" in
*":$dir:"*) ;;
*) echo "note: $dir isn't on your PATH; add  export PATH=\"$dir:\$PATH\"  to your shell's startup file" ;;
esac
