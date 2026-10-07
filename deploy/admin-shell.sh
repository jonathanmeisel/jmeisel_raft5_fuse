#!/usr/bin/env bash
# Opens the raft5 store's admin shell (`raft`) as the store's
# administrator, on a node (the first, unless named). It asks for admin's
# password: secrets/admin.pw.
#
#   ./admin-shell.sh [<node>]
. "$(dirname "$0")/lib.sh"
as_root_tty "${1:-$(first_node)}" /usr/local/sbin/raft5-shell
