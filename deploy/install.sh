#!/usr/bin/env bash
# Installs or upgrades nodes. For each node it makes the bundle (render.sh),
# sends it over SSH, and installs it there (templates/remote-install.sh),
# which restarts only what changed. It does one node at a time, and checks
# that each one serves before it starts the next. So an upgrade of every
# node keeps the cluster up.
#
#   ./install.sh [--no-check] <node>...
#   ./install.sh --all                every node, in cluster.conf's order
#   ./install.sh --bootstrap <first node>
#
# --bootstrap is for creating the cluster (see README.md): the first node
# starts with the first administrator's login. After the cluster is
# bootstrapped, install the node again without the flag, which removes that
# login. --no-check does not wait for each node to serve, which cannot
# happen before the cluster is bootstrapped.
. "$(dirname "$0")/lib.sh"

flag=""
check=true
nodes=()
for arg in "$@"; do
    case $arg in
    --bootstrap) flag=--bootstrap check=false ;;
    --no-check) check=false ;;
    --all) mapfile -t nodes < <(node_names) ;;
    -*) die "unknown option $arg" ;;
    *) nodes+=("$arg") ;;
    esac
done
((${#nodes[@]})) || die "usage: install.sh [--bootstrap | --no-check] (<node>... | --all)"
if [[ -n $flag ]] && [[ ${nodes[*]} != "$(first_node)" ]]; then
    die "--bootstrap is only for the first node, $(first_node), alone"
fi

"$DEPLOY/render.sh" "${nodes[@]}"

# Unpack into a private directory, and remove it after, because it holds
# keys.
remote="d=\$(mktemp -d); trap 'rm -rf \"\$d\"' EXIT; tar -C \"\$d\" -xzf - && sh \"\$d/remote-install.sh\" $flag"

for node in "${nodes[@]}"; do
    echo "== $node"
    tar -C "$OUT/$node" -czf - . | as_root "$node" "sh -c $(printf %q "$remote")"
    if $check; then
        if healthy "$node" 60; then
            echo "[$node] serving"
        else
            die "$node isn't serving after a minute; stopping here. Look at" \
                "journalctl -u raft5-server -u raft5fs-server on it."
        fi
    fi
done
