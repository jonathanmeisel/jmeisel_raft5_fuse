#!/usr/bin/env bash
# Runs filesystem administration on a node (the first node, unless the first
# argument names one). See templates/raft5fs-admin:
#
#   ./fsadmin.sh [<node>] user add <NAME>       prints an invitation to enrol with
#   ./fsadmin.sh [<node>] user del <NAME>
#   ./fsadmin.sh [<node>] user list
#   ./fsadmin.sh [<node>] snapshot create [<NAME>]
#   ./fsadmin.sh [<node>] snapshot del <NAME>
#   ./fsadmin.sh [<node>] snapshot list
#
# Snapshot commands ask for admin's store password (secrets/admin.pw).
. "$(dirname "$0")/lib.sh"
node=$(first_node)
if (($#)) && node_names | grep -qx -- "$1"; then
    node=$1
    shift
fi
(($#)) || die "usage: fsadmin.sh [<node>] (user | snapshot) ..."
args=$(printf '%q ' "$@")
as_root_tty "$node" "/usr/local/sbin/raft5fs-admin $args"
