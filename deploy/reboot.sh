#!/usr/bin/env bash
# Reboots nodes one at a time, waiting for each to serve again before the
# next, so the cluster stays up. Security updates install by themselves but
# never reboot; a kernel or libc update waits for this.
#
#   ./reboot.sh             every node that needs it (/var/run/reboot-required)
#   ./reboot.sh <node>...   these nodes, whether they need it or not
. "$(dirname "$0")/lib.sh"

if (($#)); then
    nodes=("$@")
else
    nodes=()
    for node in $(node_names); do
        if as_root "$node" test -f /var/run/reboot-required; then
            nodes+=("$node")
        else
            echo "[$node] doesn't need a reboot"
        fi
    done
fi

for node in "${nodes[@]}"; do
    node_field "$node" 1 >/dev/null
    healthy "$node" 10 || die "$node isn't serving now; not rebooting anything"
    echo "== rebooting $node"
    # The connection drops as the node goes down.
    as_root "$node" systemctl reboot || true
    sleep 20
    for ((i = 0; i < 60; i++)); do
        ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$(node_field "$node" 2)" true 2>/dev/null && break
        sleep 5
    done
    if healthy "$node" 120; then
        echo "[$node] serving again"
    else
        die "$node isn't serving 5 minutes after its reboot; stopping here. Look at" \
            "journalctl -u raft5-server -u raft5fs-server on it."
    fi
done
