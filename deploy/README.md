# Deploying raft5fs

Scripts for running a raft5fs cluster on ordinary Linux VMs (Debian or
Ubuntu) at any provider, usually three. Each VM runs one store node
(`raft5-server`) and one filesystem server (`raft5fs-server`), and the VMs
talk to each other over WireGuard. Losing any one VM of three loses
nothing. Users' clients are given every server's address and fail over
among them.

```
                 internet                     ┌──────── wg0 (10.10.0.0/24) ────────┐
 user's client ─── :27060 (TLS) ──▶ node1: raft5fs-server ──▶ raft5-server :27051/:27052
               ─── :27060 (TLS) ──▶ node2: raft5fs-server ──▶ raft5-server
               ─── :27060 (TLS) ──▶ node3: raft5fs-server ──▶ raft5-server
                                              └────────────────────────────────────┘
```

Only three ports are open to the internet: SSH, WireGuard (51820/udp) and
the filesystem servers (27060/tcp). The store listens only on the
WireGuard addresses, and the firewall allows its ports only on `wg0`.
Large files' data can live in an S3-compatible bucket, and backups go to
a second bucket.

A cluster has two halves:

- **this directory**, the tools: the same for every cluster;
- **a cluster repo**, the data: a private git repository holding each
  cluster's settings (`cluster.conf`) and secrets (`secrets/`), with every
  secret encrypted ("Secrets" below). The scripts find it through
  `RAFT5FS_CLUSTER`.

Every session starts the same way:

```sh
cd deploy
export RAFT5FS_CLUSTER=~/projects/raft5fs-clusters/prod
eval "$(./unlock)"        # only for scripts that read secrets; asks for the deploy passphrase
```

Your machine needs `openssl`, `wg` (the `wireguard-tools` package),
`age`, `sops`, `ssh`, Rust with the musl target, and a checkout of the
raft5 store's repository (`RAFT5_REPO` in `cluster.conf`).

## The scripts

| Script | What it does | Needs `unlock` |
|---|---|---|
| `certs.sh` | Makes every secret the cluster needs, into the cluster repo: two CAs, certificates, WireGuard keys, shared secrets, passwords. Makes only what is missing; `renew` reissues every certificate. | yes; `--ca` to sign |
| `build.sh` | Builds the server binaries, statically linked, into `out/bin`: `raft5fs-server` from this repo, `raft5-server` and `raft` from `RAFT5_REPO`. | no |
| `install.sh` | Installs or upgrades nodes over SSH, one at a time, waiting for each to serve before the next. Changes only the files that differ, and restarts only their services. `--dry-run` says what would change and changes nothing. | yes |
| `render.sh` | Builds each node's bundle into a directory; `install.sh` runs it in memory. Use it alone only to inspect a bundle (it holds secrets in plaintext). | yes |
| `unlock` | Unlocks the cluster's secrets for this shell: `eval "$(./unlock)"`, or `eval "$(./unlock --ca <file>)"` to add the CA identity. | — |
| `secrets.sh` | Makes a cluster repo, and shows, edits, adds, checks and re-keys its secrets. | to read secrets |
| `fsadmin.sh` | Filesystem administration on a node: users, snapshots, backups. | no |
| `admin-shell.sh` | Opens the store's admin shell (`raft`) on a node, as the store administrator. | no |
| `status.sh` | One look at the cluster's health: services, failed units, pending reboots, certificate expiry, disk, memory, swap, backups, and drift from the cluster repo. | for the drift check |
| `reboot.sh` | Reboots the nodes that need it, one at a time, each checked. | no |
| `get-raft5fs.sh` | Installs the `raft5fs` client from the newest GitHub release, checked against its checksums. | no |
| `check.sh` | Runs shellcheck on every script here; CI runs it on every change to `deploy/`. | no |
| `templates/` | What gets installed on the nodes: the systemd units, `raft5fs-admin`, `raft5-shell`, the certificate check, the nightly backup, and the node-side installer. | — |

A script that needs `unlock` and doesn't have it stops before doing
anything, and says so.

## Secrets

### The cluster repo

```
raft5fs-clusters/          a private GitHub repo
  .sops.yaml               which age identity opens which secret
  .githooks/pre-commit     refuses a plaintext secret, or a .sops file that isn't encrypted
  .gitignore               ignores plaintext secrets (*.key, *.pw, *.secret, *.env)
  prod/                    one directory per cluster
    cluster.conf           the cluster's settings (from cluster.conf.example)
    authorized_keys        SSH public keys for the nodes' admin user
    secrets/               certificates, keys, passwords (below)
```

In `secrets/`, certificates and public keys are plain files. Every secret
is kept only as a sops-encrypted `<name>.sops`, one file each, so a diff
shows which secret changed. The scripts decrypt them into a temporary
directory in memory, which is deleted when they exit, however they exit:
plaintext secrets never touch the disk. Commit and push the cluster repo
after every change.

### The age identities

| Identity | Kept | Opens | Used for |
|---|---|---|---|
| deploy | `~/.config/raft5fs/age/deploy.age`, passphrase-protected | everything but the CA keys and the operator backup key | every install |
| CA | offline if you can (a USB drive); otherwise a separate file with its own passphrase, e.g. `~/.config/raft5fs/age/ca.age` | the CA keys and `operator/backup.key` | signing certificates; opening a backup |
| recovery | a password manager (and paper); never on the laptop | everything | getting back in after losing the laptop or a passphrase |

`eval "$(./unlock)"` decrypts the deploy identity once (one passphrase)
into this shell's environment only. `eval "$(./unlock --ca <file>)"` adds
the CA identity; the examples below use `/media/usb/ca.age`, so put the
path of yours in its place. "Using the recovery key", at the end, says
how to get back in when an identity is lost.

### What's in `secrets/`

| File | What it is | Opens with | Where it goes |
|---|---|---|---|
| `internal-ca.pem`, `internal-ca.key.sops`, `internal-ca.srl` | The store's own CA, for mTLS between the nodes, and from the filesystem servers and the admin shell to the store. Nothing outside the cluster sees it. | CA | `.pem` on every node |
| `nodes/<node>.pem`, `nodes/<node>.key.sops` | Each node's certificate, for its WireGuard address, signed by `internal-ca` | deploy | that node |
| `fs-ca.pem`, `fs-ca.key.sops`, `fs-ca.srl` | The CA for the filesystem servers' public port. Users trust `fs-ca.pem`: it is in their invitations and profiles. | CA | `.pem` on every node |
| `fs.pem`, `fs.key.sops`, `fs.san` | The filesystem servers' certificate, covering every node's public name and IP (`fs.san` records which) | deploy | every node |
| `wg/<node>.key.sops`, `wg/<node>.pub` | Each node's WireGuard key pair | deploy | that node's `wg0.conf`, and its peers' |
| `jwt.secret.sops` | Signs the store's login tokens | deploy | every node (raft5-server) |
| `token.key.sops` | Signs users' sessions on the filesystem servers. Anyone holding it can act as any user (though still not read anything). | deploy | every node (raft5fs-server) |
| `admin.pw.sops` | The store administrator's password, for `admin-shell.sh` | deploy | only on the first node, while bootstrapping |
| `store.pw.sops` | The password of the store account the filesystem servers use (`raft5fs`) | deploy | every node |
| `s3.env.sops` | The large-files bucket's key (`RAFT5FS_OBJECT_ACCESS_KEY`, `..._SECRET_KEY`), if there is a bucket | deploy | every node |
| `s3-ca.pem` | That bucket's CA, if private (optional) | — | every node |
| `backup.env.sops` | The backup bucket's key (`RAFT5FS_BACKUP_ACCESS_KEY`, `..._SECRET_KEY`) | deploy | every node, for `raft5fs-admin` only |
| `backup.pub` | The operator public key backups are sealed to | — | every node |
| `backup-ca.pem` | The backup bucket's CA, if private (optional) | — | every node |
| `operator/backup.key.sops` | The operator private key: the only way to open a backup's store contents | CA | nowhere: used on your machine to restore |

`.sops.yaml` decides each file's identities by path. `certs.sh` writes
the certificates, keys, `jwt.secret`, `token.key` and the passwords. You
add the bucket keys and the operator key yourself.

### Handling secrets

| Task | Command |
|---|---|
| Print one | `./secrets.sh show admin.pw` |
| Edit one (made if missing) | `./secrets.sh edit s3.env` |
| Add a file | `./secrets.sh put backup-ca.pem ./ca.pem` |
| Check every secret is encrypted and opens | `./secrets.sh check` |
| Re-encrypt to the identities in `.sops.yaml` (after changing them) | `./secrets.sh updatekeys` |

After changing a secret, install it with `./install.sh --dry-run --all`
then `./install.sh --all`, and commit the cluster repo.

## Creating and deploying a new cluster

**1. Make the VMs.** Three, say, with Debian or Ubuntu and your SSH key
for root. Note their public IPs. Give them DNS names (`fs1`, `fs2`, `fs3`)
if you can: users' profiles list the servers' addresses, and names
survive a change of IP. Test the disks before trusting them, because
every write waits on the disk:

```sh
fio --name=sync --rw=write --bs=4k --size=64m --fsync=1 --filename=/root/fio.test
```

Low single-digit milliseconds of fsync latency is good; tens of
milliseconds makes every write slow.

**2. Make the cloud firewall,** in front of each VM's own (`ufw`). On
DigitalOcean: Networking → Firewalls, applied to the VMs:

| Direction | Protocol | Port | Sources |
|---|---|---|---|
| Inbound | TCP | 22 (SSH) | all |
| Inbound | TCP | 27060 (filesystem) | all |
| Inbound | UDP | 51820 (WireGuard) | the nodes' public IPs only |
| Outbound | ICMP, TCP, UDP | all | all |

**3. Make the age identities,** once per operator, not per cluster:

```sh
mkdir -p -m 700 ~/.config/raft5fs/age
age-keygen | age -p >~/.config/raft5fs/age/deploy.age   # the deploy passphrase
age-keygen | age -p >/media/usb/ca.age                 # a different passphrase
age-keygen -o /dev/shm/recovery.txt                    # copy the AGE-SECRET-KEY line into
shred -u /dev/shm/recovery.txt                         #   your password manager first
```

The public keys (`age1...`): `age-keygen` prints the recovery one; for
the others, `age -d <file> | age-keygen -y`.

**4. Make the cluster repo:**

```sh
./secrets.sh init ~/projects/raft5fs-clusters prod \
    --deploy age1... --ca age1... --recovery age1...
cp cluster.conf.example ~/projects/raft5fs-clusters/prod/cluster.conf
cp ~/.ssh/id_ed25519.pub ~/projects/raft5fs-clusters/prod/authorized_keys
gh repo create raft5fs-clusters --private --source ~/projects/raft5fs-clusters
export RAFT5FS_CLUSTER=~/projects/raft5fs-clusters/prod
```

Edit `cluster.conf`: `NODES` (name, public IP, WireGuard IP, DNS name or
`-`), `RAFT5_REPO`, `CHUNK_SIZE`. Leave `SSH_USER=root` and
`SSH_HARDEN=no` for now, and set `ADMIN_USER=admin`. A node's name and
WireGuard address can't change after bootstrap, so pick them once.

**5. Large files (optional).** To keep files' data past `OBJECT_FROM`
(10 MiB) in an S3-compatible bucket, in objects of `OBJECT_BLOCK` (16
MiB): make a private bucket that supports conditional writes
(`If-None-Match`; AWS S3, DigitalOcean Spaces and current MinIO do), and
a key that can read, write, delete and list under `S3_PREFIX`. Set
`S3_BUCKET`, `S3_ENDPOINT`, `S3_REGION` (and `S3_PATH_STYLE=yes` for
MinIO), then:

```sh
./secrets.sh edit s3.env      # RAFT5FS_OBJECT_ACCESS_KEY=...  RAFT5FS_OBJECT_SECRET_KEY=...
```

Users' machines must reach `S3_ENDPOINT`. `OBJECT_FROM` and
`OBJECT_BLOCK` are fixed by the first server to use them. Bigger blocks
mean fewer objects, but a block is rewritten whole for any change in it:
16 MiB suits files written front to back (media, archives); databases
and VM images, which make small random writes, do better with 4 MiB.
Turning on bucket versioning, with noncurrent versions expiring after a
few days, is a safety net for garbage collection. See SETUP.txt section
12 for how it works.

**6. Make the secrets and build:**

```sh
eval "$(./unlock --ca /media/usb/ca.age)"      # signing needs the CA identity
./certs.sh
rustup target add x86_64-unknown-linux-musl    # once; also install musl-gcc
./build.sh
```

**7. Install.** The first node gets the bootstrap login; the others can't
serve until the store is bootstrapped, hence `--no-check`:

```sh
./install.sh --bootstrap node1
./install.sh --no-check node2 node3
```

Each node now has `wg0` up, its firewall on, the admin user, and both
services installed. `raft5fs-server` keeps restarting until step 8.

**8. Bootstrap the store.** The admin shell asks for
`./secrets.sh show admin.pw`; `create_user` asks for
`./secrets.sh show store.pw`:

```sh
./admin-shell.sh node1
raft> bootstrap node1
raft> add_server https://10.10.0.2:27052
raft> add_server https://10.10.0.3:27052
raft> endpoints
raft> create_user raft5fs
raft> acl_set "" user:raft5fs=write
raft> group_add backup-operators user:raft5fs
raft> quit
```

`endpoints` should list every node. `acl_set ""` gives every key to the
filesystem servers' account and no one else. `backup-operators` lets that
account take snapshots and backups, so day-to-day work never needs the
store administrator.

**9. Finish:** `./install.sh --all` removes the bootstrap login from node1
and checks every node. The first filesystem server to start creates the
filesystem.

**10. Harden SSH.** Check the admin user works on every node, then switch
to it, then turn root and password logins off:

```sh
ssh admin@<node> sudo -n true                  # on each node
$EDITOR $RAFT5FS_CLUSTER/cluster.conf          # SSH_USER=admin
./install.sh --dry-run --all                   # works as admin; nothing would change
$EDITOR $RAFT5FS_CLUSTER/cluster.conf          # SSH_HARDEN=yes
./install.sh --all
```

`install.sh` refuses `SSH_HARDEN=yes` while `SSH_USER=root`, so this
order can't lock you out. Keep a second key in `authorized_keys`, and a
way in through the provider's console, in case your laptop's key is
lost.

**11. Backups and swap.** Set up backups ("Backup and recovery"), then set
`NIGHTLY_BACKUPS=yes`, and `SWAP_SIZE=1G` on small VMs, and
`./install.sh --all`.

**12. Add users** ("Users" below), and commit and push the cluster repo.

## Adding a node

1. **Make the VM,** with your SSH key for root, and add its public IP to
   the cloud firewall's WireGuard rule.
2. **Make its admin user by hand.** The scripts log in as `ADMIN_USER`,
   which a new VM doesn't have yet:

   ```sh
   ssh root@<new IP> 'getent group admin >/dev/null && g="-g admin"; id admin || useradd -m -s /bin/bash $g admin
     install -d -m 700 -o admin -g "$(id -gn admin)" ~admin/.ssh
     cat >~admin/.ssh/authorized_keys; chown admin ~admin/.ssh/authorized_keys; chmod 600 ~admin/.ssh/authorized_keys
     echo "admin ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/raft5fs-admin; chmod 440 /etc/sudoers.d/raft5fs-admin' \
     <$RAFT5FS_CLUSTER/authorized_keys
   ssh admin@<new IP> sudo -n true
   ```

   (Ubuntu has an `admin` group already; the `-g` handles that.)
3. **Add it to `NODES`** in `cluster.conf`, with the next free WireGuard
   address, then make its certificate and WireGuard key. This also
   reissues the filesystem servers' certificate to cover the new address:

   ```sh
   eval "$(./unlock --ca /media/usb/ca.age)"
   ./certs.sh
   ```

4. **Update the existing nodes first,** so they have the new WireGuard
   peer and certificate: `./install.sh node1 node2 node3`.
5. **Install the new node:** `./install.sh --no-check node4`. It runs idle:
   it isn't a member yet.
6. **Add it to the store:** in `./admin-shell.sh`, run
   `add_server https://10.10.0.4:27052`, then `endpoints`.
7. **Check:** `./install.sh node4` (nothing to change; it waits for the
   node to serve), then `./status.sh`. Commit the cluster repo.

Users' clients learn the new server only from their profile: give them
its address, or new invitations. Odd sizes are the useful ones: three
nodes survive one failure, five survive two.

## Rotating certificates

Leaf certificates (each node's, and the filesystem servers') last
`CERT_DAYS` (default 397); the CAs last ten years. Each node checks daily
(`raft5fs-cert-check.timer`) and fails that unit 30 days before expiry;
`./status.sh` shows the days left. Both servers read certificates only
at startup, so renewing reinstalls, one node at a time:

```sh
eval "$(./unlock --ca /media/usb/ca.age)"
./certs.sh renew
./install.sh --dry-run --all          # the certificates, and restarts of both servers
./install.sh --all
git -C $RAFT5FS_CLUSTER add -A && git -C $RAFT5FS_CLUSTER commit -m "renew certificates" && git -C $RAFT5FS_CLUSTER push
```

The CAs stay the same, so users need nothing new. Changing a node's
public name or IP in `cluster.conf`, then `./certs.sh`, reissues the
filesystem servers' certificate by itself.

## Building and deploying new server binaries

```sh
git -C ../../jmeisel_raft5 pull       # if raft5 changed
./build.sh
eval "$(./unlock)"
./install.sh --dry-run --all          # the binaries, and restarts of their services
./install.sh --all
```

`install.sh` installs a binary whenever its bytes differ from the node's,
whatever version it reports, and restarts only that service, one node at
a time with a health check between: the cluster stays up. A node that
doesn't serve again within a minute stops the run.

`raft5fs-server` uses the raft5 client library at the commit `Cargo.lock`
pins, but `build.sh` builds `raft5-server` from `RAFT5_REPO` as it is
checked out. Keep that checkout at the pinned commit
(`grep -A2 'name = "raft5-client"' ../Cargo.lock`), so the store and the
filesystem servers come from the same raft5.

**Client releases.** The `raft5fs` client isn't built here. The `release`
workflow tests every push, and on a `v*` tag builds it for Linux, macOS
and Android and attaches the binaries to that GitHub release. To release,
bump `version` in the workspace `Cargo.toml` (the tag must match it),
then:

```sh
git commit -am "release 0.2.0" && git tag v0.2.0 && git push && git push origin v0.2.0
```

Users install or update with `get-raft5fs.sh` (SETUP.txt section 1).

## Backup and recovery

The cluster keeps three copies, which protects against a dead disk, not
a mistake: a bad deletion or a bug reaches every node at once. Snapshots
help with deletions, but they live on the cluster. A backup copies a
snapshot to a separate bucket: the store's contents, sealed to the
operator key, and every object the snapshot points to. Backups share
objects, so each copies only what is new.

### Setting up

1. **Make a backup bucket,** not `S3_BUCKET`, ideally in another region,
   with a key that can read, write, delete and list under
   `BACKUP_PREFIX`.
2. **Make the operator key pair.** The private key goes into the cluster
   repo sealed to the CA and recovery identities only, so neither the
   deploy identity nor the nodes can open it:

   ```sh
   k=$XDG_RUNTIME_DIR/operator.key
   ./out/bin/raft5fs-server backup keygen $k
   ./secrets.sh put operator/backup.key $k
   ./secrets.sh put backup.pub $k.pub
   shred -u $k $k.pub
   ```

3. **Configure:** set `BACKUP_BUCKET`, `BACKUP_ENDPOINT`, `BACKUP_REGION`
   (and `BACKUP_PATH_STYLE=yes` for MinIO), then:

   ```sh
   ./secrets.sh edit backup.env   # RAFT5FS_BACKUP_ACCESS_KEY=...  RAFT5FS_BACKUP_SECRET_KEY=...
   ./install.sh --all
   ```

4. **Turn on nightly backups:** `NIGHTLY_BACKUPS=yes` (and `BACKUP_KEEP`,
   default 14), then `./install.sh --all`. Every node gets a timer, 03:00
   UTC on the first node and 20 minutes later on each next. It snapshots
   the filesystem as `nightly-<date>`, backs the snapshot up, removes the
   snapshot, and deletes `nightly-*` backups beyond the newest
   `BACKUP_KEEP`. The first node to run does the work; the others find it
   done. A failure fails the unit (`./status.sh` shows it;
   `journalctl -u raft5fs-nightly-backup` says why).

### By hand

```sh
./fsadmin.sh snapshot create before-cleanup
./fsadmin.sh backup create before-cleanup
./fsadmin.sh snapshot del before-cleanup   # the backup doesn't need it
./fsadmin.sh backup list
./fsadmin.sh backup del before-cleanup     # also deletes objects no other backup uses
```

Only one backup job runs at a time, on any node. A backup is whole once
its manifest is written; one that fails part way leaves no backup, and
the next `backup del` cleans up after it. Nightly backups never delete
backups with other names.

**Check a backup opens,** now and then (it needs the CA identity):

```sh
eval "$(./unlock --ca /media/usb/ca.age)"
. $RAFT5FS_CLUSTER/cluster.conf
eval "$(./secrets.sh show backup.env | sed 's/^/export /')"
./out/bin/raft5fs-server backup fetch-kv nightly-2026-10-24 /dev/shm/kv.test \
    --backup-private-key <(./secrets.sh show operator/backup.key) \
    --backup-endpoint "$BACKUP_ENDPOINT" --backup-bucket "$BACKUP_BUCKET" \
    --backup-region "$BACKUP_REGION" --backup-prefix "$BACKUP_PREFIX"
shred -u /dev/shm/kv.test
```

### Restoring

After losing the cluster, the bucket, or both:

1. **Make new VMs and install them,** following "Creating and deploying a
   new cluster" steps 1, 2, 6 and 7, with the cluster repo you have. New
   VMs only have root SSH: set `SSH_USER=root` and `SSH_HARDEN=no` for
   now. If the public IPs changed, update `NODES` and run `./certs.sh`
   with the CA identity, which reissues the public certificate. Users'
   profiles then need the new addresses too, unless the nodes have DNS
   names.
2. **Put the objects back,** before anything serves, if the
   large-files bucket was lost:

   ```sh
   ./fsadmin.sh backup restore-objects nightly-2026-10-24
   ```

   This copies them into `S3_BUCKET` under `S3_PREFIX`, which must be
   what the backed-up filesystem used.
3. **Open the store backup** on your machine, as in "Check a backup
   opens", but write it to `/dev/shm/store.backup`, then copy it to the
   first node:

   ```sh
   scp /dev/shm/store.backup root@<node1 IP>:/root/
   ```

4. **Bootstrap from it:**

   ```sh
   ./admin-shell.sh node1
   raft> bootstrap node1 --restore-from /root/store.backup
   raft> add_server https://10.10.0.2:27052
   raft> add_server https://10.10.0.3:27052
   raft> quit
   ```

   Accounts, groups and ACLs come back with it, so there's no
   `create_user` or `group_add` to do.
5. **Finish:** `./install.sh --all`, then harden SSH again (step 10 of
   "Creating"), and delete `store.backup`, on the node and in
   `/dev/shm`: it holds the store's contents in clear. Snapshots don't
   come back.

Practise this once on a scratch cluster before relying on it.

## Day-to-day operations

### Checking on the cluster

Nothing alerts yet, so look now and then (weekly, say):

```sh
./status.sh            # ends with "all good", or lists what needs attention
```

It shows, for each node, its services, failed units (a failed nightly
backup or certificate check shows here), a pending reboot, the days until
the first certificate expires, disk, memory and swap; for the cluster,
the snapshot count and the newest backup's age; and, if unlocked, any
drift from the cluster repo. `--no-drift` skips the drift check.

### Users

```sh
./fsadmin.sh user add alice      # prints an invitation
./fsadmin.sh user list
./fsadmin.sh user del alice      # also removes every grant made to her
```

An invitation holds the one-time enrolment code, the servers' addresses
and `fs-ca.pem`: it is as secret as the code, so hand it to alice alone.
She installs the client (`get-raft5fs.sh`) and runs
`raft5fs enrol '<invitation>'` (SETUP.txt section 5). A new code for an
existing user lets them enrol again after forgetting their password.

### Snapshots

```sh
./fsadmin.sh snapshot create before-upgrade
./fsadmin.sh snapshot list
./fsadmin.sh snapshot del before-upgrade
```

Every client shows snapshots read-only at `/.snapshot/<name>`. Until it
is removed, a snapshot keeps every old version of everything changed
since, and the store holds at most 32.

### Reboots and updates

Security updates install on each node daily; nodes never reboot by
themselves, because a reboot outside `reboot.sh` takes a node down
without checking the others are up. When `./status.sh` reports a pending
reboot:

```sh
./reboot.sh            # only the nodes that need it, one at a time, each checked
```

### Changing settings or secrets

Edit `$RAFT5FS_CLUSTER/cluster.conf`, or a secret with
`./secrets.sh edit`, then:

```sh
./install.sh --dry-run --all      # says what would change and restart; changes nothing
./install.sh --all
git -C $RAFT5FS_CLUSTER commit -am "..." && git -C $RAFT5FS_CLUSTER push
```

`install.sh` changes only files that differ, restarts only their
services, and applies WireGuard peer changes in place. A node's own
WireGuard address can't change that way.

### The store's admin shell

```sh
./secrets.sh show admin.pw        # the password it asks for
./admin-shell.sh [<node>]
```

Rarely needed: cluster membership (`endpoints`, `add_server`), store
accounts, ACLs and groups.

### Looking at a node

```sh
ssh admin@<node> sudo journalctl -u raft5fs-server -n 50
ssh admin@<node> sudo journalctl -u raft5-server -n 50
ssh admin@<node> systemctl --failed
ssh admin@<node> sudo raft5fs-cert-check
```

## Using the recovery key

Every secret is also encrypted to the recovery identity, so it opens
everything, including the CA keys and the operator backup key. Use it
when another identity is gone:

- the laptop is lost or broken, and `deploy.age` with it;
- a passphrase is forgotten;
- the CA identity is lost.

Use it only for the time it takes, on a machine you trust, and keep it
out of files and shell history. `read -rs` takes it without echoing it
or recording it:

```sh
read -rs SOPS_AGE_KEY && export SOPS_AGE_KEY     # paste the AGE-SECRET-KEY-... line, then Enter
./secrets.sh check                               # everything opens, nothing "locked"
```

With `SOPS_AGE_KEY` set, every script works as if unlocked, with the CA
identity too. When done, `unset SOPS_AGE_KEY`, or close the terminal.

**Replacing a lost identity,** e.g. on a new laptop:

1. Clone the cluster repo, and set `RAFT5FS_CLUSTER` to its cluster
   directory.
2. Make the new identity, as when creating a cluster:

   ```sh
   mkdir -p -m 700 ~/.config/raft5fs/age
   age-keygen | age -p >~/.config/raft5fs/age/deploy.age     # a new deploy passphrase
   age -d ~/.config/raft5fs/age/deploy.age | age-keygen -y   # its public key
   ```

3. In `.sops.yaml`, replace the lost identity's public key (`age1...`) with
   the new one: in the comment at the top, and in every `age:` line it
   appears in.
4. Load the recovery key as above, and re-encrypt every secret to the
   identities now in `.sops.yaml`:

   ```sh
   ./secrets.sh updatekeys
   ./secrets.sh check
   unset SOPS_AGE_KEY
   ```

5. Commit and push. From now on, `eval "$(./unlock)"` works with the new
   identity.

A lost CA identity is replaced the same way, with its own passphrase and
its own `age:` line. A forgotten passphrase is a lost identity too.

**If an identity may have leaked,** rather than been lost: replace it as
above. That stops it opening any secret from now on. But the secrets'
old encryptions are still in the cluster repo's git history, and the
leaked identity still opens those. So also change the secrets it could
open:
- certificates: `./certs.sh renew`
- passwords: `./secrets.sh edit`, and change them in the store
- bucket keys: new keys from your provider

Then reinstall. The same goes for the recovery key itself: if it
leaks, make a new one, put it in `.sops.yaml`, and run
`./secrets.sh updatekeys` with the deploy and CA identities unlocked.
