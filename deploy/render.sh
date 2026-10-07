#!/usr/bin/env bash
# Assembles each node's bundle -- binaries, certificates, secrets, units,
# WireGuard config -- into out/<node>/, from cluster.conf, secrets/ and
# templates/. install.sh runs it; run it alone to see what would be
# installed.
#
#   ./render.sh [<node>...]     every node if none are named
. "$(dirname "$0")/lib.sh"

[[ -f $SECRETS/internal-ca.pem ]] || die "no secrets yet: run ./certs.sh first"
for bin in raft5-server raft raft5fs-server; do
    [[ -x $OUT/bin/$bin ]] || die "no $OUT/bin/$bin: run ./build.sh first"
done

# Fills in templates/$1's placeholders for node $2.
fill() {
    local wg_ip
    wg_ip=$(node_field "$2" 3)
    sed -e "s|@NODE@|$2|g" \
        -e "s|@WG_IP@|$wg_ip|g" \
        -e "s|@SEEDS@|$(store_seeds)|g" \
        -e "s|@CHUNK_SIZE@|$CHUNK_SIZE|g" \
        "$DEPLOY/templates/$1"
}

render() {
    local node=$1 dir=$OUT/$1 wg_ip
    wg_ip=$(node_field "$node" 3)
    [[ -f $SECRETS/nodes/$node.pem ]] ||
        die "no certificate for $node: run ./certs.sh after adding it to cluster.conf"
    umask 077
    rm -rf "$dir"
    mkdir -p "$dir"/{bin,raft5,raft5fs,systemd,sbin}

    cp "$OUT/bin/"{raft5-server,raft,raft5fs-server} "$dir/bin/"

    for d in raft5 raft5fs; do
        cp "$SECRETS/nodes/$node.pem" "$dir/$d/node.pem"
        cp "$SECRETS/nodes/$node.key" "$dir/$d/node.key"
        cp "$SECRETS/internal-ca.pem" "$dir/$d/internal-ca.pem"
    done
    cp "$SECRETS/jwt.secret" "$dir/raft5/"
    cp "$SECRETS/fs.pem" "$SECRETS/fs.key" "$SECRETS/token.key" "$dir/raft5fs/"
    echo "RAFT5FS_STORE_PASSWORD=$(cat "$SECRETS/store.pw")" >"$dir/raft5fs/store.env"

    # Only the first node bootstraps the cluster, and only it ever needs
    # the first administrator's password (install.sh --bootstrap).
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
        raft5fs-cert-check.service raft5fs-cert-check.timer; do
        fill "$unit" "$node" >"$dir/systemd/$unit"
    done
    for script in raft5fs-admin raft5-shell raft5fs-cert-check; do
        fill "$script" "$node" >"$dir/sbin/$script"
    done
    fill remote-install.sh "$node" >"$dir/remote-install.sh"
    {
        echo "NODE=$node"
        echo "SSH_PORT=$SSH_PORT"
        echo "WG_PORT=$WG_PORT"
    } >"$dir/node.conf"
    echo "rendered $dir"
}

if (($# == 0)); then
    set -- $(node_names)
fi
for node in "$@"; do
    render "$node"
done
