#!/usr/bin/env bash
# Checks every script here with shellcheck: the bash scripts run on your
# machine, and the POSIX sh templates run on the nodes. CI runs it too
# (.github/workflows/deploy-scripts.yml).
#
#   ./check.sh
set -euo pipefail
cd "$(dirname "$0")"

command -v shellcheck >/dev/null || { echo "check.sh: shellcheck isn't installed" >&2 && exit 1; }
shellcheck -x ./*.sh unlock
# The templates source files that exist only on the nodes (SC1091).
shellcheck -s sh -e SC1091 templates/remote-install.sh templates/raft5fs-admin \
    templates/raft5-shell templates/raft5fs-cert-check templates/raft5fs-nightly-backup \
    templates/raft5fs-web-cert
echo "every script passes shellcheck"
