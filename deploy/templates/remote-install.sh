#!/bin/sh
# Runs on a node, as root, from the bundle that install.sh unpacked there.
# It installs the bundle and starts or restarts what changed. Debian or
# Ubuntu.
#
#   remote-install.sh [--bootstrap] [--dry-run]
#
# --bootstrap starts the store node with the first administrator's login, to
# bootstrap the cluster. Without it, any such login left from a bootstrap is
# removed.
#
# --dry-run changes nothing. It says which files would change and which
# services would restart. It names files only, never their contents.
set -eu
cd "$(dirname "$0")"
. ./node.conf

bootstrap=false
dry=false
for arg in "$@"; do
    case $arg in
    --bootstrap) bootstrap=true ;;
    --dry-run) dry=true ;;
    *) echo "remote-install.sh: unknown option $arg" >&2 && exit 2 ;;
    esac
done

say() { echo "[$NODE] $*"; }

# Whether --dry-run found anything to do.
would=false

# Runs a command that changes the node, or with --dry-run says it would.
act() {
    if $dry; then
        say "would run: $*"
        would=true
    else
        "$@"
    fi
}

# -- packages and users -------------------------------------------------
missing=""
for pkg in wireguard-tools ufw openssl unattended-upgrades; do
    dpkg -s "$pkg" >/dev/null 2>&1 || missing="$missing $pkg"
done
if [ -n "$missing" ]; then
    if $dry; then
        say "would install:$missing"
        would=true
    else
        say "installing$missing"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q
        # shellcheck disable=SC2086
        apt-get install -yq $missing
    fi
fi
for user in raft5 raft5fs; do
    id "$user" >/dev/null 2>&1 ||
        act useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
done

# -- files ----------------------------------------------------------------
# Each changed file is recorded in $changed, by the service it belongs to.
changed=""

# put SRC DEST MODE OWNER:GROUP SERVICE: installs SRC at DEST if it is
# different. It replaces the file atomically, because a running binary
# cannot be written over, only replaced.
put() {
    src=$1 dest=$2 mode=$3 owner=$4 service=$5
    if [ -f "$dest" ] && cmp -s "$src" "$dest"; then
        if $dry; then
            [ "$(stat -c '%a %U:%G' "$dest")" = "$(printf '%o' "0$mode") $owner" ] ||
                say "would fix the mode or owner of $dest"
            return
        fi
        chmod "$mode" "$dest"
        chown "$owner" "$dest"
        return
    fi
    changed="$changed $service"
    if $dry; then
        say "would change $dest"
        return
    fi
    install -m "$mode" -o "${owner%:*}" -g "${owner#*:}" "$src" "$dest.new"
    mv -f "$dest.new" "$dest"
}

# Removes DEST, if it exists, for SERVICE.
unput() {
    dest=$1 service=$2
    [ -e "$dest" ] || return 0
    changed="$changed $service"
    if $dry; then
        say "would remove $dest"
    else
        say "removing $dest"
        rm -f "$dest"
    fi
}

for d in "0750 raft5 /etc/raft5" "0750 raft5fs /etc/raft5fs" "0700 root /etc/wireguard"; do
    # shellcheck disable=SC2086
    set -- $d
    # Also sets the mode of a directory that exists.
    if ! $dry || [ ! -d "$3" ]; then
        act install -d -m "$1" -o root -g "$2" "$3"
    fi
done

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
# The object store's CA, if it has a private one (cluster.conf's S3_*
# settings).
if [ -f raft5fs/s3-ca.pem ]; then
    put raft5fs/s3-ca.pem /etc/raft5fs/s3-ca.pem 0644 root:root raft5fs-server
fi
put raft5fs/fs-ca.pem /etc/raft5fs/fs-ca.pem 0644 root:root raft5fs-admin
# The backup space's settings (cluster.conf's BACKUP_* settings), for
# raft5fs-admin alone.
if [ -f raft5fs/backup.env ]; then
    put raft5fs/backup.env /etc/raft5fs/backup.env 0600 root:root raft5fs-admin
    put raft5fs/backup.pub /etc/raft5fs/backup.pub 0644 root:root raft5fs-admin
fi
if [ -f raft5fs/backup-ca.pem ]; then
    put raft5fs/backup-ca.pem /etc/raft5fs/backup-ca.pem 0644 root:root raft5fs-admin
fi

if $bootstrap; then
    put bootstrap/admin.pw /etc/raft5/admin.pw 0640 root:raft5 raft5-server
    printf '%s\n' 'RAFT5_BOOTSTRAP_ARGS=--initial-admin-user admin --initial-admin-password-file /etc/raft5/admin.pw' \
        >bootstrap.env
    put bootstrap.env /etc/raft5/bootstrap.env 0640 root:raft5 raft5-server
else
    # The bootstrap login stops working once the cluster exists.
    unput /etc/raft5/bootstrap.env raft5-server
    unput /etc/raft5/admin.pw raft5-server
fi

put wg0.conf /etc/wireguard/wg0.conf 0600 root:root wg0

for unit in raft5-server.service raft5fs-server.service; do
    put "systemd/$unit" "/etc/systemd/system/$unit" 0644 root:root "${unit%.service}"
done
for unit in raft5fs-cert-check.service raft5fs-cert-check.timer; do
    put "systemd/$unit" "/etc/systemd/system/$unit" 0644 root:root cert-check
done
for unit in raft5fs-nightly-backup.service raft5fs-nightly-backup.timer; do
    put "systemd/$unit" "/etc/systemd/system/$unit" 0644 root:root nightly-backup
done
for script in raft5fs-admin raft5-shell raft5fs-cert-check raft5fs-nightly-backup; do
    put "sbin/$script" "/usr/local/sbin/$script" 0755 root:root scripts
done

# -- hardening ------------------------------------------------------------
# Security updates install daily; nothing reboots by itself.
put harden/apt.conf /etc/apt/apt.conf.d/52raft5fs 0644 root:root apt

# The admin user that SSH_USER switches to, with your keys and sudo.
if [ -n "$ADMIN_USER" ]; then
    if ! id "$ADMIN_USER" >/dev/null 2>&1; then
        # Ubuntu ships an `admin` group: use a group of that name as the
        # user's own, rather than fail to make it.
        if getent group "$ADMIN_USER" >/dev/null; then
            act useradd --create-home --shell /bin/bash --gid "$ADMIN_USER" "$ADMIN_USER"
        else
            act useradd --create-home --shell /bin/bash "$ADMIN_USER"
        fi
    fi
    home=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
    home=${home:-/home/$ADMIN_USER}
    [ -d "$home/.ssh" ] || act install -d -m 0700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$home/.ssh"
    put harden/authorized_keys "$home/.ssh/authorized_keys" 0600 "$ADMIN_USER:$ADMIN_USER" admin-user
    # A broken sudoers file stops sudo working for everyone: check it first.
    visudo -cqf harden/sudoers || { say "the sudoers line for $ADMIN_USER doesn't parse" && exit 1; }
    put harden/sudoers /etc/sudoers.d/raft5fs-admin 0440 root:root admin-user
else
    unput /etc/sudoers.d/raft5fs-admin admin-user
fi

# SSH: keys only, no root login. Only with a working admin user, or no one
# could log in.
if [ "$SSH_HARDEN" = yes ]; then
    if [ -z "$ADMIN_USER" ]; then
        say "not hardening SSH: no ADMIN_USER to log in as"
        exit 1
    fi
    # Its keys were installed just above; with --dry-run they may not be yet.
    if ! $dry && [ ! -s "$home/.ssh/authorized_keys" ]; then
        say "not hardening SSH: $ADMIN_USER has no authorized_keys"
        exit 1
    fi
    put harden/sshd.conf /etc/ssh/sshd_config.d/10-raft5fs.conf 0644 root:root ssh
else
    unput /etc/ssh/sshd_config.d/10-raft5fs.conf ssh
fi

# -- swap -------------------------------------------------------------------
# A swap file, so a memory spike (a large backup, say) slows the node down
# rather than getting a server killed. Low swappiness: used only under
# pressure. With SWAP_SIZE empty, swap is left as it is.
if [ -n "${SWAP_SIZE:-}" ]; then
    want=$(numfmt --from=iec "$SWAP_SIZE")
    have=$(stat -c %s /swapfile 2>/dev/null || echo 0)
    active=false
    swapon --show=NAME --noheadings | grep -qx /swapfile && active=true
    if [ "$have" != "$want" ]; then
        if $dry; then
            say "would make a $SWAP_SIZE swap file at /swapfile"
            would=true
        else
            say "making a $SWAP_SIZE swap file at /swapfile"
            if $active && ! swapoff /swapfile; then
                say "can't swap the old /swapfile out (not enough free memory?); leaving it"
                exit 1
            fi
            active=false
            rm -f /swapfile
            fallocate -l "$SWAP_SIZE" /swapfile
            chmod 600 /swapfile
            mkswap -q /swapfile
        fi
    fi
    if ! grep -q '^/swapfile ' /etc/fstab; then
        if $dry; then
            say "would add /swapfile to /etc/fstab"
            would=true
        else
            echo '/swapfile none swap sw 0 0' >>/etc/fstab
        fi
    fi
    if ! $active && ! $dry; then
        swapon /swapfile
    fi
    put harden/swap-sysctl.conf /etc/sysctl.d/60-raft5fs-swap.conf 0644 root:root sysctl
fi

has() { case " $changed " in *" $1 "*) return 0 ;; esac; return 1; }

# Whether the nightly backup timer should run here.
backups_wanted() { [ "$NIGHTLY_BACKUPS" = yes ] && [ -f raft5fs/backup.env ]; }

if $dry; then
    if backups_wanted && ! systemctl is-enabled -q raft5fs-nightly-backup.timer 2>/dev/null; then
        say "would turn nightly backups on"
        would=true
    elif ! backups_wanted && systemctl is-enabled -q raft5fs-nightly-backup.timer 2>/dev/null; then
        say "would turn nightly backups off"
        would=true
    fi
    restarts=""
    for s in wg0 raft5-server raft5fs-server ssh; do
        case $s in
        raft5-server | raft5fs-server) systemctl is-active -q "$s" || changed="$changed $s" ;;
        esac
        has "$s" && restarts="$restarts $s"
    done
    if [ -z "$changed" ] && ! $would; then
        say "nothing would change"
    elif [ -n "$restarts" ]; then
        say "would restart or reload:$restarts"
    fi
    exit 0
fi

if has ssh; then
    if ! sshd -t; then
        rm -f /etc/ssh/sshd_config.d/10-raft5fs.conf
        say "sshd rejected the new settings; removed them"
        exit 1
    fi
    say "reloading ssh"
    systemctl try-reload-or-restart ssh
fi

if has sysctl; then
    sysctl -q -p /etc/sysctl.d/60-raft5fs-swap.conf
fi

# -- WireGuard -------------------------------------------------------------
if systemctl is-active -q wg-quick@wg0; then
    # Apply changes in place: stopping wg0 would remove the store's address
    # while the store uses it.
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
# Only SSH, WireGuard, and the filesystem servers' port are open to the
# world. The store's ports are open only on wg0. (The store binds to the
# WireGuard address anyway, so this is a second protection.)
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
if backups_wanted; then
    systemctl enable -q --now raft5fs-nightly-backup.timer
elif systemctl is-enabled -q raft5fs-nightly-backup.timer 2>/dev/null; then
    say "turning nightly backups off"
    systemctl disable -q --now raft5fs-nightly-backup.timer
fi

if has raft5-server || ! systemctl is-active -q raft5-server; then
    say "restarting raft5-server"
    systemctl restart raft5-server
fi
if has raft5fs-server || ! systemctl is-active -q raft5fs-server; then
    say "restarting raft5fs-server"
    systemctl restart raft5fs-server
fi
say "installed"
