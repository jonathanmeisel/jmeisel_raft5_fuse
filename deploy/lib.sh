# shellcheck shell=bash
# Shared by the scripts here: reads the cluster's settings and gives the
# paths for files. Source it; do not run it.
#
# The cluster lives in its own repository (README "Cluster repo"):
# RAFT5FS_CLUSTER names the directory that holds cluster.conf and
# secrets/. Secret files there are sops-encrypted (*.sops). `open_secrets`
# decrypts them into a temporary directory in memory, which is deleted
# when the script exits.

set -euo pipefail

DEPLOY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Used by the scripts that source this file.
# shellcheck disable=SC2034
REPO=$(cd "$DEPLOY/.." && pwd)
# shellcheck disable=SC2034
OUT=$DEPLOY/out

die() {
    echo "$(basename "$0"): $*" >&2
    exit 1
}

[[ -n ${RAFT5FS_CLUSTER:-} ]] ||
    die "set RAFT5FS_CLUSTER to the cluster's directory in the cluster repo (README \"Cluster repo\")"
CLUSTER=$(cd "$RAFT5FS_CLUSTER" && pwd) || die "RAFT5FS_CLUSTER ($RAFT5FS_CLUSTER) isn't a directory"
[[ -f $CLUSTER/cluster.conf ]] || die "no cluster.conf in $CLUSTER"
# The encrypted secrets. `open_secrets` sets SECRETS to their plaintext.
STORE=$CLUSTER/secrets
SECRETS=
# shellcheck source=cluster.conf.example
. "$CLUSTER/cluster.conf"

# Whether path $1 (under secrets/) holds a secret, so it is kept only
# sops-encrypted. Everything else (certificates, public keys) is public.
is_secret() {
    case $1 in
    *.key | *.pw | *.secret | *.env) return 0 ;;
    *) return 1 ;;
    esac
}

# Whether path $1 is sealed to the offline CA identity, not the deploy one:
# it opens only after `unlock --ca`.
needs_ca_identity() {
    case $1 in
    internal-ca.key | fs-ca.key | operator/*) return 0 ;;
    *) return 1 ;;
    esac
}

# sops on one secret file, run from the cluster directory so that sops
# finds .sops.yaml above it. The files hold raw bytes, so the plaintext
# side is "binary"; the encrypted side is sops's JSON.
sops_decrypt() {
    (cd "$CLUSTER" && sops decrypt --input-type json --output-type binary "$1")
}

# Encrypts stdin as secrets/$1.sops, with the recipients that .sops.yaml
# gives that path.
sops_encrypt() {
    local rel=$1 dest=$STORE/$1.sops
    mkdir -p "$(dirname "$dest")"
    (cd "$CLUSTER" && sops encrypt --input-type binary --output-type json \
        --filename-override "secrets/$rel.sops" /dev/stdin) >"$dest.new"
    mv -f "$dest.new" "$dest"
}

# Decrypts the cluster's secrets into a new temporary directory in memory,
# and points SECRETS at it. Removed when the script exits, however it
# exits. Files sealed to the CA identity are skipped unless it is unlocked.
open_secrets() {
    command -v sops >/dev/null || die "sops isn't installed"
    [[ -d $STORE ]] || die "no secrets in $CLUSTER yet: run ./certs.sh"
    [[ -n ${SOPS_AGE_KEY:-}${SOPS_AGE_KEY_FILE:-} ]] ||
        die "the secrets are locked: run  eval \"\$(./unlock)\"  first"
    SECRETS=$(mktemp -d -p "${XDG_RUNTIME_DIR:-/dev/shm}" raft5fs-secrets.XXXXXX)
    trap 'rm -rf "$SECRETS"' EXIT
    local rel plain
    while IFS= read -r rel; do
        if [[ $rel == *.sops ]]; then
            plain=${rel%.sops}
            mkdir -p "$SECRETS/$(dirname "$plain")"
            if ! sops_decrypt "secrets/$rel" >"$SECRETS/$plain" 2>/dev/null; then
                rm -f "$SECRETS/$plain"
                needs_ca_identity "$plain" && continue
                die "cannot decrypt secrets/$rel with the unlocked identities"
            fi
        else
            mkdir -p "$SECRETS/$(dirname "$rel")"
            cp -p "$STORE/$rel" "$SECRETS/$rel"
        fi
    done < <(cd "$STORE" && find . -type f | sed 's|^\./||' | sort)
    # What each file held, so `seal_secrets` writes back only what changed.
    (cd "$SECRETS" && find . -type f -exec sha256sum {} + | sed 's|  \./|  |') >"$SECRETS/.opened"
}

# Writes new and changed files in SECRETS back to the cluster: secrets
# sops-encrypted, everything else as it is. Unchanged files are left alone,
# because each encryption differs and would show as a change in git. Sets
# SEALED to how many files it wrote.
SEALED=0
seal_secrets() {
    local rel sum
    SEALED=0
    while IFS= read -r rel; do
        sum=$(sha256sum <"$SECRETS/$rel")
        grep -qxF "${sum%% *}  $rel" "$SECRETS/.opened" && continue
        if is_secret "$rel"; then
            sops_encrypt "$rel" <"$SECRETS/$rel"
            echo "sealed secrets/$rel.sops"
        else
            mkdir -p "$STORE/$(dirname "$rel")"
            cp -p "$SECRETS/$rel" "$STORE/$rel"
            echo "wrote secrets/$rel"
        fi
        SEALED=$((SEALED + 1))
    done < <(cd "$SECRETS" && find . -type f ! -name .opened | sed 's|^\./||' | sort)
}

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
    [[ -n $line ]] || die "no node $1 in $CLUSTER/cluster.conf"
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

# raft5fs-server's backup options, from cluster.conf. None unless
# BACKUP_BUCKET is set. Values must not contain spaces.
backup_options() {
    if [[ -z ${BACKUP_BUCKET:-} ]]; then
        return 0
    fi
    [[ -n ${BACKUP_ENDPOINT:-} ]] || die "BACKUP_BUCKET is set but BACKUP_ENDPOINT isn't, in cluster.conf"
    printf -- '--backup-endpoint %s --backup-bucket %s ' "$BACKUP_ENDPOINT" "$BACKUP_BUCKET"
    if [[ -n ${BACKUP_REGION:-} ]]; then printf -- '--backup-region %s ' "$BACKUP_REGION"; fi
    if [[ ${BACKUP_PATH_STYLE:-no} == yes ]]; then printf -- '--backup-path-style '; fi
    if [[ -n ${BACKUP_PREFIX:-} ]]; then printf -- '--backup-prefix %s ' "$BACKUP_PREFIX"; fi
    if [[ -f $SECRETS/backup-ca.pem ]]; then printf -- '--backup-ca /etc/raft5fs/backup-ca.pem '; fi
    printf -- '--backup-public-key /etc/raft5fs/backup.pub '
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
    # The command runs on the node, so it is meant to expand there.
    # shellcheck disable=SC2029
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
