#!/usr/bin/env bash
# Puts together each node's bundle (binaries, certificates, secrets, units,
# WireGuard config) in DIR/<node>/, from the cluster's settings and
# secrets, and templates/. install.sh runs it into a temporary directory
# in memory. Run it alone to see what would be installed, and remove DIR
# after: the bundles hold the secrets in plaintext.
#
#   ./render.sh --out DIR [<node>...]     every node if none are named
. "$(dirname "$0")/lib.sh"

[[ ${1:-} == --out && -n ${2:-} ]] || die "usage: render.sh --out DIR [<node>...]"
BUNDLES=$2
shift 2
mkdir -p "$BUNDLES"
open_secrets

[[ -f $SECRETS/internal-ca.pem ]] || die "no secrets yet: run ./certs.sh first"
if [[ -n ${S3_BUCKET:-} ]]; then
    [[ -f $SECRETS/s3.env ]] ||
        die "S3_BUCKET is set: add the bucket's credentials with ./secrets.sh edit s3.env (README \"Large files\")"
    for var in RAFT5FS_OBJECT_ACCESS_KEY RAFT5FS_OBJECT_SECRET_KEY; do
        grep -q "^$var=" "$SECRETS/s3.env" || die "secrets/s3.env has no $var="
    done
    object_options >/dev/null
fi
if [[ -n ${BACKUP_BUCKET:-} ]]; then
    [[ -f $SECRETS/backup.env ]] ||
        die "BACKUP_BUCKET is set: add the backup bucket's credentials with ./secrets.sh edit backup.env (README \"Backups\")"
    for var in RAFT5FS_BACKUP_ACCESS_KEY RAFT5FS_BACKUP_SECRET_KEY; do
        grep -q "^$var=" "$SECRETS/backup.env" || die "secrets/backup.env has no $var="
    done
    [[ -f $SECRETS/backup.pub ]] ||
        die "BACKUP_BUCKET is set: put the operator public key in the cluster's secrets/backup.pub (README \"Backups\")"
    [[ $BACKUP_BUCKET != "${S3_BUCKET:-}" ]] || die "BACKUP_BUCKET must not be S3_BUCKET"
    backup_options >/dev/null
fi
# Node hardening (README "Hardening the nodes"). Off unless set.
ADMIN_USER=${ADMIN_USER:-}
SSH_HARDEN=${SSH_HARDEN:-no}
NIGHTLY_BACKUPS=${NIGHTLY_BACKUPS:-no}
BACKUP_KEEP=${BACKUP_KEEP:-14}
SWAP_SIZE=${SWAP_SIZE:-}
[[ -z $SWAP_SIZE || $SWAP_SIZE =~ ^[1-9][0-9]*[MG]$ ]] ||
    die "SWAP_SIZE ($SWAP_SIZE) must be a size like 512M or 1G"
if [[ -n $ADMIN_USER ]]; then
    [[ $ADMIN_USER =~ ^[a-z][a-z0-9_-]*$ ]] || die "ADMIN_USER ($ADMIN_USER) isn't a valid user name"
    [[ -s $CLUSTER/authorized_keys ]] ||
        die "ADMIN_USER is set: put the SSH public keys it accepts in $CLUSTER/authorized_keys"
fi
if [[ $SSH_HARDEN == yes ]]; then
    [[ -n $ADMIN_USER ]] || die "SSH_HARDEN=yes needs ADMIN_USER, or no one could log in"
fi
if [[ $NIGHTLY_BACKUPS == yes ]]; then
    [[ -n ${BACKUP_BUCKET:-} ]] || die "NIGHTLY_BACKUPS=yes needs the backup space (BACKUP_BUCKET)"
    [[ $BACKUP_KEEP =~ ^[1-9][0-9]*$ ]] || die "BACKUP_KEEP must be at least 1"
fi

for bin in raft5-server raft raft5fs-server; do
    [[ -x $OUT/bin/$bin ]] || die "no $OUT/bin/$bin: run ./build.sh first"
done

# Fills in the placeholders in templates/$1 for node $2.
fill() {
    local wg_ip
    wg_ip=$(node_field "$2" 3)
    sed -e "s|@NODE@|$2|g" \
        -e "s|@WG_IP@|$wg_ip|g" \
        -e "s|@SEEDS@|$(store_seeds)|g" \
        -e "s|@CHUNK_SIZE@|$CHUNK_SIZE|g" \
        -e "s|@INVITE_SERVERS@|$(invite_servers)|g" \
        -e "s|@OBJECT_OPTIONS@|$(object_options)|g" \
        -e "s|@BACKUP_OPTIONS@|$(backup_options)|g" \
        -e "s|@BACKUP_KEEP@|$BACKUP_KEEP|g" \
        -e "s|@BACKUP_TIME@|$(backup_time "$2")|g" \
        "$DEPLOY/templates/$1"
}

# When node $1 runs the nightly backup: 03:00 for the first node, then 20
# minutes later for each one after, so one node does the work.
backup_time() {
    local i
    i=$(node_names | grep -nx -- "$1" | cut -d: -f1)
    printf '%02d:%02d:00' $((3 + (i - 1) * 20 / 60)) $(((i - 1) * 20 % 60))
}

render() {
    local node=$1 dir=$BUNDLES/$1 wg_ip
    wg_ip=$(node_field "$node" 3)
    [[ -f $SECRETS/nodes/$node.pem ]] ||
        die "no certificate for $node: run ./certs.sh after adding it to cluster.conf"
    umask 077
    rm -rf "$dir"
    mkdir -p "$dir"/{bin,raft5,raft5fs,systemd,sbin,harden}

    cp "$OUT/bin/"{raft5-server,raft,raft5fs-server} "$dir/bin/"

    for d in raft5 raft5fs; do
        cp "$SECRETS/nodes/$node.pem" "$dir/$d/node.pem"
        cp "$SECRETS/nodes/$node.key" "$dir/$d/node.key"
        cp "$SECRETS/internal-ca.pem" "$dir/$d/internal-ca.pem"
    done
    cp "$SECRETS/jwt.secret" "$dir/raft5/"
    cp "$SECRETS/fs.pem" "$SECRETS/fs.key" "$SECRETS/token.key" "$dir/raft5fs/"
    # Public: it goes into users' invitations.
    cp "$SECRETS/fs-ca.pem" "$dir/raft5fs/"
    echo "RAFT5FS_STORE_PASSWORD=$(cat "$SECRETS/store.pw")" >"$dir/raft5fs/store.env"
    if [[ -n ${S3_BUCKET:-} ]]; then
        grep -E '^RAFT5FS_OBJECT_(ACCESS|SECRET)_KEY=' "$SECRETS/s3.env" >>"$dir/raft5fs/store.env"
        if [[ -f $SECRETS/s3-ca.pem ]]; then
            cp "$SECRETS/s3-ca.pem" "$dir/raft5fs/"
        fi
    fi
    # Only raft5fs-admin reads these, not the serving units.
    if [[ -n ${BACKUP_BUCKET:-} ]]; then
        grep -E '^RAFT5FS_BACKUP_(ACCESS|SECRET)_KEY=' "$SECRETS/backup.env" >"$dir/raft5fs/backup.env"
        cp "$SECRETS/backup.pub" "$dir/raft5fs/"
        if [[ -f $SECRETS/backup-ca.pem ]]; then
            cp "$SECRETS/backup-ca.pem" "$dir/raft5fs/"
        fi
    fi

    # Only the first node bootstraps the cluster, and only it needs the
    # first administrator's password (install.sh --bootstrap).
    if [[ $node == "$(first_node)" ]]; then
        mkdir -p "$dir/bootstrap"
        cp "$SECRETS/admin.pw" "$dir/bootstrap/"
    fi

    {
        echo "[Interface]"
        echo "# $node"
        echo "Address = $wg_ip/24"
        echo "ListenPort = $WG_PORT"
        echo "PrivateKey = $(cat "$SECRETS/wg/$node.key")"
        while read -r peer public_ip peer_wg_ip _; do
            [[ $peer == "$node" ]] && continue
            echo
            echo "[Peer]"
            echo "# $peer"
            echo "PublicKey = $(cat "$SECRETS/wg/$peer.pub")"
            echo "Endpoint = $public_ip:$WG_PORT"
            echo "AllowedIPs = $peer_wg_ip/32"
            echo "PersistentKeepalive = 25"
        done < <(nodes)
    } >"$dir/wg0.conf"

    for unit in raft5-server.service raft5fs-server.service \
        raft5fs-cert-check.service raft5fs-cert-check.timer \
        raft5fs-nightly-backup.service raft5fs-nightly-backup.timer; do
        fill "$unit" "$node" >"$dir/systemd/$unit"
    done
    for script in raft5fs-admin raft5-shell raft5fs-cert-check raft5fs-nightly-backup; do
        fill "$script" "$node" >"$dir/sbin/$script"
    done
    fill remote-install.sh "$node" >"$dir/remote-install.sh"

    # Hardening. remote-install.sh uses each only when its setting is on.
    if [[ -n $ADMIN_USER ]]; then
        cp "$CLUSTER/authorized_keys" "$dir/harden/authorized_keys"
        echo "$ADMIN_USER ALL=(ALL) NOPASSWD:ALL" >"$dir/harden/sudoers"
    fi
    printf '%s\n' \
        '# raft5fs: SSH keys only, and no root login (deploy/README.md).' \
        'PermitRootLogin no' \
        'PasswordAuthentication no' \
        'KbdInteractiveAuthentication no' >"$dir/harden/sshd.conf"
    printf '%s\n' \
        '// raft5fs: install security updates daily; never reboot by itself' \
        '// (deploy/reboot.sh reboots one node at a time).' \
        'APT::Periodic::Update-Package-Lists "1";' \
        'APT::Periodic::Unattended-Upgrade "1";' \
        'Unattended-Upgrade::Automatic-Reboot "false";' >"$dir/harden/apt.conf"
    printf '%s\n' \
        '# raft5fs: use the swap file only under memory pressure.' \
        'vm.swappiness = 10' >"$dir/harden/swap-sysctl.conf"

    {
        echo "NODE=$node"
        echo "SSH_PORT=$SSH_PORT"
        echo "WG_PORT=$WG_PORT"
        echo "ADMIN_USER=$ADMIN_USER"
        echo "SSH_HARDEN=$SSH_HARDEN"
        echo "NIGHTLY_BACKUPS=$NIGHTLY_BACKUPS"
        echo "SWAP_SIZE=$SWAP_SIZE"
    } >"$dir/node.conf"
    echo "rendered $dir"
}

if (($# == 0)); then
    mapfile -t all < <(node_names)
    set -- "${all[@]}"
fi
for node in "$@"; do
    render "$node"
done
