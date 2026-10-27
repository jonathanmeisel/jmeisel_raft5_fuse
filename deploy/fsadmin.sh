#!/usr/bin/env bash
# Runs filesystem administration on a node (the first node, unless the first
# argument names one). See templates/raft5fs-admin:
#
#   ./fsadmin.sh [<node>] user add <NAME> [--no-volumes] [--invite] [--links]
#                                               prints an invitation to enrol with
#   ./fsadmin.sh [<node>] user set <NAME> [--volumes on|off] [--invite on|off] [--links on|off]
#   ./fsadmin.sh [<node>] user del <NAME>
#   ./fsadmin.sh [<node>] user list
#   ./fsadmin.sh [<node>] snapshot create [<NAME>]
#   ./fsadmin.sh [<node>] snapshot del <NAME>
#   ./fsadmin.sh [<node>] snapshot list
#   ./fsadmin.sh [<node>] backup create <SNAPSHOT>
#   ./fsadmin.sh [<node>] backup del <NAME>
#   ./fsadmin.sh [<node>] backup list
#   ./fsadmin.sh [<node>] backup restore-objects <NAME>
. "$(dirname "$0")/lib.sh"
node=$(first_node)
if (($#)) && node_names | grep -qx -- "$1"; then
    node=$1
    shift
fi
(($#)) || die "usage: fsadmin.sh [<node>] (user | snapshot | backup) ..."
args=$(printf '%q ' "$@")
as_root_tty "$node" "/usr/local/sbin/raft5fs-admin $args"
