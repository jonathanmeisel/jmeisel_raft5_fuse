# Shared by the scripts here: reads cluster.conf and gives the paths for
# files. Source it; do not run it.

set -euo pipefail

DEPLOY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$DEPLOY/.." && pwd)
SECRETS=$DEPLOY/secrets
OUT=$DEPLOY/out

die() {
    echo "$(basename "$0"): $*" >&2
    exit 1
}

[[ -f $DEPLOY/cluster.conf ]] ||
    die "no cluster.conf: copy cluster.conf.example to cluster.conf and edit it"
# shellcheck source=cluster.conf.example
. "$DEPLOY/cluster.conf"

# Every node, one line each: name public_ip wg_ip public_name.
nodes() {
    grep -v '^[[:space:]]*$' <<<"$NODES"
}

node_names() {
    nodes | awk '{print $1}'
}

# The first node, where the cluster is bootstrapped.
first_node() {
    node_names | head -n1
}

# Field $2 of node $1's line (2 = public IP, 3 = WireGuard IP, 4 = name).
node_field() {
    local line
    line=$(nodes | awk -v n="$1" '$1 == n') || true
    [[ -n $line ]] || die "no node $1 in cluster.conf"
    awk -v f="$2" '{print $f}' <<<"$line"
}

# The store's client API addresses, used as the filesystem servers' seeds.
store_seeds() {
    nodes | awk '{printf "%shttps://%s:27051", (NR > 1 ? " " : ""), $3}'
}

# The invite options for `raft5fs-server user add`: every node's public
# filesystem address. (The CA comes from /etc/raft5fs.)
invite_servers() {
    local node
    for node in $(node_names); do
        printf -- '--invite-server https://%s:27060 ' "$(public_address "$node")"
    done
}

# raft5fs-server's object storage options, from cluster.conf. None unless
# S3_BUCKET is set. Values must not contain spaces.
object_options() {
    if [[ -z ${S3_BUCKET:-} ]]; then
        return 0
    fi
    [[ -n ${S3_ENDPOINT:-} ]] || die "S3_BUCKET is set but S3_ENDPOINT isn't, in cluster.conf"
    printf -- '--object-endpoint %s --object-bucket %s ' "$S3_ENDPOINT" "$S3_BUCKET"
    if [[ -n ${S3_REGION:-} ]]; then printf -- '--object-region %s ' "$S3_REGION"; fi
    if [[ ${S3_PATH_STYLE:-no} == yes ]]; then printf -- '--object-path-style '; fi
    if [[ -n ${S3_PREFIX:-} ]]; then printf -- '--object-prefix %s ' "$S3_PREFIX"; fi
    if [[ -n ${OBJECT_FROM:-} ]]; then printf -- '--object-from %s ' "$OBJECT_FROM"; fi
    if [[ -n ${OBJECT_BLOCK:-} ]]; then printf -- '--object-block %s ' "$OBJECT_BLOCK"; fi
    if [[ -n ${GC_INTERVAL:-} ]]; then printf -- '--gc-interval %s ' "$GC_INTERVAL"; fi
    if [[ -f $SECRETS/s3-ca.pem ]]; then printf -- '--object-ca /etc/raft5fs/s3-ca.pem '; fi
}

# The address that users connect to for node $1.
public_address() {
    local name
    name=$(node_field "$1" 4)
    if [[ $name == - ]]; then node_field "$1" 2; else echo "$name"; fi
}

ssh_node() {
    local node=$1
    shift
    ssh "$SSH_USER@$(node_field "$node" 2)" "$@"
}

# Runs the rest as root on node $1, through sudo unless the login is root.
as_root() {
    local node=$1
    shift
    if [[ $SSH_USER == root ]]; then
        ssh_node "$node" "$@"
    else
        ssh_node "$node" sudo "$@"
    fi
}

# Same as `as_root`, with a terminal, for commands that ask for a password.
as_root_tty() {
    local node=$1
    shift
    local sudo=()
    [[ $SSH_USER == root ]] || sudo=(sudo)
    ssh -t "$SSH_USER@$(node_field "$node" 2)" "${sudo[@]}" "$@"
}

# Whether node $1 is serving: both its services run, and its own store node
# answers a read sent only through it with the filesystem servers' store
# account. That read needs the cluster to have a leader. Waits up to $2
# seconds.
healthy() {
    local node=$1 wait=${2:-30} i seed
    seed=https://$(node_field "$node" 3):27051
    for ((i = 0; i < wait; i += 3)); do
        if as_root "$node" systemctl is-active -q raft5-server raft5fs-server &&
            as_root "$node" env RAFT5FS_SEEDS="$seed" \
                /usr/local/sbin/raft5fs-admin user list >/dev/null 2>&1; then
            return 0
        fi
        sleep 3
    done
    return 1
}
