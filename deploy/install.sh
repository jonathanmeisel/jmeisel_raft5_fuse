#!/usr/bin/env bash
# Installs or upgrades nodes: renders each one's bundle (render.sh), sends
# it over SSH, and installs it there (templates/remote-install.sh), which
# restarts only what changed. Nodes are done one at a time, each checked
# to be serving before the next is touched, so upgrading every node keeps
# the cluster up.
#
#   ./install.sh [--no-check] <node>...
#   ./install.sh --all                every node, in cluster.conf's order
#   ./install.sh --bootstrap <first node>
#
# --bootstrap is for creating the cluster (see README.md): the first node
# starts with the first administrator's login. Install it again without
# the flag once the cluster is bootstrapped, which removes that login.
# --no-check skips waiting for each node to serve, which can't happen
# before the cluster is bootstrapped.
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

# Unpacked into a private directory, removed afterwards: it holds keys.
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
