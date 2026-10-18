#!/bin/sh
# Runs on a node, as root, from the bundle install.sh unpacked there:
# installs it, and (re)starts what it changed. Debian or Ubuntu.
#
#   remote-install.sh [--bootstrap]
#
# --bootstrap starts the store node with the first administrator's login,
# for bootstrapping the cluster; without it, any such login left from a
# bootstrap is removed.
set -eu
cd "$(dirname "$0")"
. ./node.conf

bootstrap=false
[ "${1:-}" = --bootstrap ] && bootstrap=true

say() { echo "[$NODE] $*"; }

# -- packages and users -------------------------------------------------
if ! command -v wg-quick >/dev/null || ! command -v ufw >/dev/null; then
    say "installing wireguard-tools and ufw"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -yq wireguard-tools ufw openssl
fi
for user in raft5 raft5fs; do
    id "$user" >/dev/null 2>&1 ||
        useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
done

# -- files ----------------------------------------------------------------
# A changed file is noted in $changed, by the service it belongs to.
changed=""

# put SRC DEST MODE OWNER:GROUP SERVICE: installs SRC at DEST if it
# differs, replacing it atomically -- a running binary can't be written
# over, only replaced.
put() {
    src=$1 dest=$2 mode=$3 owner=$4 service=$5
    if [ -f "$dest" ] && cmp -s "$src" "$dest"; then
        chmod "$mode" "$dest"
        chown "$owner" "$dest"
        return
    fi
    install -m "$mode" -o "${owner%:*}" -g "${owner#*:}" "$src" "$dest.new"
    mv -f "$dest.new" "$dest"
    changed="$changed $service"
}

install -d -m 0750 -o root -g raft5 /etc/raft5
install -d -m 0750 -o root -g raft5fs /etc/raft5fs
install -d -m 0700 /etc/wireguard

for bin in raft5-server raft; do
    put "bin/$bin" "/usr/local/bin/$bin" 0755 root:root raft5-server
done
put bin/raft5fs-server /usr/local/bin/raft5fs-server 0755 root:root raft5fs-server

for f in node.pem node.key internal-ca.pem jwt.secret; do
    put "raft5/$f" "/etc/raft5/$f" 0640 root:raft5 raft5-server
done
for f in node.pem node.key internal-ca.pem fs.pem fs.key token.key; do
    put "raft5fs/$f" "/etc/raft5fs/$f" 0640 root:raft5fs raft5fs-server
done
put raft5fs/store.env /etc/raft5fs/store.env 0600 root:root raft5fs-server
# The object store's CA, if it has a private one (cluster.conf's S3_*).
if [ -f raft5fs/s3-ca.pem ]; then
    put raft5fs/s3-ca.pem /etc/raft5fs/s3-ca.pem 0644 root:root raft5fs-server
fi
put raft5fs/fs-ca.pem /etc/raft5fs/fs-ca.pem 0644 root:root raft5fs-admin

if $bootstrap; then
    put bootstrap/admin.pw /etc/raft5/admin.pw 0640 root:raft5 raft5-server
    printf '%s\n' 'RAFT5_BOOTSTRAP_ARGS=--initial-admin-user admin --initial-admin-password-file /etc/raft5/admin.pw' \
        >bootstrap.env
    put bootstrap.env /etc/raft5/bootstrap.env 0640 root:raft5 raft5-server
elif [ -e /etc/raft5/bootstrap.env ] || [ -e /etc/raft5/admin.pw ]; then
    say "removing the bootstrap login"
    rm -f /etc/raft5/bootstrap.env /etc/raft5/admin.pw
    changed="$changed raft5-server"
fi

put wg0.conf /etc/wireguard/wg0.conf 0600 root:root wg0

for unit in raft5-server.service raft5fs-server.service; do
    put "systemd/$unit" "/etc/systemd/system/$unit" 0644 root:root "${unit%.service}"
done
for unit in raft5fs-cert-check.service raft5fs-cert-check.timer; do
    put "systemd/$unit" "/etc/systemd/system/$unit" 0644 root:root cert-check
done
for script in raft5fs-admin raft5-shell raft5fs-cert-check; do
    put "sbin/$script" "/usr/local/sbin/$script" 0755 root:root scripts
done

has() { case " $changed " in *" $1 "*) return 0 ;; esac; return 1; }

# -- WireGuard -------------------------------------------------------------
if systemctl is-active -q wg-quick@wg0; then
    # Applied in place: tearing wg0 down would take the store's address
    # out from under it.
    if has wg0; then
        say "updating wg0's peers"
        wg syncconf wg0 /dev/stdin <<WG
$(wg-quick strip wg0)
WG
    fi
else
    say "starting wg0"
    systemctl enable -q --now wg-quick@wg0
fi

# -- firewall --------------------------------------------------------------
# Only SSH, WireGuard and the filesystem servers' port are open to the
# world; the store's ports only on wg0. (The store binds to the WireGuard
# address anyway: this is the second guard.)
ufw allow "$SSH_PORT/tcp" >/dev/null
ufw allow "$WG_PORT/udp" >/dev/null
ufw allow 27060/tcp >/dev/null
ufw allow in on wg0 to any port 27051:27052 proto tcp >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw --force enable >/dev/null

# -- services ----------------------------------------------------------------
systemctl daemon-reload
systemctl enable -q raft5-server raft5fs-server raft5fs-cert-check.timer
systemctl start raft5fs-cert-check.timer

if has raft5-server || ! systemctl is-active -q raft5-server; then
    say "restarting raft5-server"
    systemctl restart raft5-server
fi
if has raft5fs-server || ! systemctl is-active -q raft5fs-server; then
    say "restarting raft5fs-server"
    systemctl restart raft5fs-server
fi
say "installed"
