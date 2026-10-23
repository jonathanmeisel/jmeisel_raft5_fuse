# Deploying raft5fs on three VMs

Scripts for running raft5fs on three ordinary Linux VMs at any provider.
Each VM runs one store node (`raft5-server`) and one filesystem server
(`raft5fs-server`), and the VMs talk to each other over WireGuard. Each
VM runs both services, so losing any one VM loses nothing. Users' mounts
are given all three servers' addresses and fail over among them.

```
                 internet                     ┌──────── wg0 (10.10.0.0/24) ────────┐
 user's mount ──── :27060 (TLS) ──▶ node1: raft5fs-server ──▶ raft5-server :27051/:27052
              ──── :27060 (TLS) ──▶ node2: raft5fs-server ──▶ raft5-server
              ──── :27060 (TLS) ──▶ node3: raft5fs-server ──▶ raft5-server
                                              └────────────────────────────────────┘
```

Only three ports are open to the internet: SSH, WireGuard (51820/udp) and
the filesystem servers (27060/tcp). The store listens only on the
WireGuard addresses, and the firewall allows its ports only on `wg0`.

The VMs need Debian or Ubuntu, and SSH as root or as a user with
passwordless sudo. Your machine needs `openssl`, `wg` (the
`wireguard-tools` package), `age`, `sops`, Rust, and a checkout of the
raft5 store's repository.

## What's here

| File | What it does |
|---|---|
| `cluster.conf.example` | The cluster's layout: nodes, addresses, ports. Copy it into the cluster repo and edit. |
| `unlock` | Unlocks the cluster's secrets for this shell: `eval "$(./unlock)"`. |
| `secrets.sh` | Makes the cluster repo, and shows, edits, checks and re-keys its secrets. |
| `certs.sh` | Makes every secret: two CAs, certificates, WireGuard keys, shared secrets and passwords, into the cluster repo. `certs.sh renew` reissues the certificates. |
| `build.sh` | Builds static (musl) binaries into `out/bin`. |
| `render.sh` | Assembles each node's bundle into a directory. `install.sh` runs it for you, in memory. |
| `install.sh` | Installs or upgrades nodes over SSH, one at a time, checking each is serving before moving on. `--dry-run` shows what would change. |
| `reboot.sh` | Reboots the nodes that need it after security updates, one at a time. |
| `check.sh` | Runs shellcheck on every script here (CI runs it too). |
| `admin-shell.sh` | Opens the store's admin shell (`raft`) on a node. |
| `fsadmin.sh` | Manages users, snapshots and backups: `user add/del/list`, `snapshot create/del/list`, `backup create/del/list/restore-objects`. |
| `templates/` | The systemd units, the scripts installed on the nodes, and the node-side installer. |

A cluster's settings and secrets aren't here: they live in a separate,
private cluster repo (next section). Only `out/bin` is made here, and it
is git-ignored.

## Cluster repo

Each cluster is a directory in a private git repo, e.g.
`raft5fs-clusters/prod/`, holding `cluster.conf` and `secrets/`. Every
script here reads it from `RAFT5FS_CLUSTER`:

```sh
export RAFT5FS_CLUSTER=~/projects/raft5fs-clusters/prod
eval "$(./unlock)"            # asks for the deploy passphrase once
```

In `secrets/`, certificates and public keys are plain files. Every
secret (`*.key`, `*.pw`, `*.secret`, `*.env`) is stored only as a
sops-encrypted `<name>.sops`, with age. The scripts decrypt them into a
temporary directory in memory, deleted when they exit, so plaintext
secrets never land on disk.

Three age identities can open them:

| Identity | Where | Opens |
|---|---|---|
| deploy | `~/.config/raft5fs/age/deploy.age`, passphrase-protected | everything except the CA keys and the operator backup key |
| CA | offline (USB drive, plus paper) | the CA keys and `operator/backup.key` |
| recovery | paper and a password manager; never on the laptop | everything |

The repo's `.sops.yaml` says which identity opens what. Signing a
certificate (`certs.sh`) or opening a backup's store contents needs the
CA identity: `eval "$(./unlock --ca /media/usb/ca.age)"`.

Everyday commands:

| Task | Command |
|---|---|
| Print a secret | `./secrets.sh show admin.pw` |
| Edit one (made if missing) | `./secrets.sh edit s3.env` |
| Add a file | `./secrets.sh put backup-ca.pem ./ca.pem` |
| Check everything is encrypted and opens | `./secrets.sh check` |
| After changing `.sops.yaml` (e.g. a new laptop) | `./secrets.sh updatekeys` |

**Making the repo and identities**, once:

```sh
mkdir -p ~/.config/raft5fs/age
age-keygen | age -p >~/.config/raft5fs/age/deploy.age   # choose a passphrase
age-keygen -o /media/usb/ca.age                        # offline; copy to paper too
age-keygen                                             # recovery: write it on paper and in a
                                                       # password manager, then clear the terminal
./secrets.sh init ~/projects/raft5fs-clusters prod \
    --deploy age1... --ca age1... --recovery age1...
cp cluster.conf.example ~/projects/raft5fs-clusters/prod/cluster.conf
gh repo create raft5fs-clusters --private --source ~/projects/raft5fs-clusters
```

`age-keygen` prints each public key (`age1...`); for the deploy identity,
`age -d ~/.config/raft5fs/age/deploy.age | age-keygen -y` shows it. The
repo's pre-commit hook refuses a plaintext secret, and its `.gitignore`
ignores them. Commit and push after every change to `secrets/`.

**Moving an existing `deploy/secrets/` in:** with the repo made as
above, the deploy identity unlocked, and `cluster.conf` copied in:

```sh
./secrets.sh import ./secrets            # from deploy/, where the old copy is
./secrets.sh put operator/backup.key ~/offline/raft5fs-backup.key
./secrets.sh check
```

Then check that `./install.sh --all` changes nothing on the nodes, commit
and push, and only then `shred -u` the old plaintext copies.

## The certificates

There are two CAs, kept apart:

- **internal-ca** is the store's own. Each node gets one certificate for
  its WireGuard address, which it uses in three roles:
  - as a store node, for peer mTLS and client mTLS;
  - as the filesystem server logging in to the store;
  - for the admin shell.

  Nothing outside the cluster ever needs this CA.
- **fs-ca** covers the filesystem servers' public port. One certificate
  covers every node's public name and IP. Users get `fs-ca.pem` from the
  cluster's `secrets/`, and mount with `--ca fs-ca.pem`.

Certificates last `CERT_DAYS` (default 397). The CAs last ten years.
Each node runs a daily check, `raft5fs-cert-check.timer`, that fails
(visible in `systemctl --failed` and the journal) once any certificate is
within 30 days of expiring. Both servers read their certificates only at
startup, so renewing means reinstalling, which restarts them one node at
a time. Renewing signs certificates, so it needs the CA identity:

```sh
eval "$(./unlock --ca /media/usb/ca.age)"
./certs.sh renew
./install.sh --all
```

Commit and push the cluster repo after.

Changing nodes' public names or IPs in `cluster.conf` and running
`./certs.sh` reissues the public certificate by itself.

## First deployment

**1. Make three VMs.** Note their public IPs. If you have a domain, point
`fs1`, `fs2` and `fs3` at them. Test their disks before trusting them,
because every write waits on the disk:

```sh
fio --name=sync --rw=write --bs=4k --size=64m --fsync=1 --filename=/root/fio.test
```

Look at the fsync latency percentiles. Low single-digit milliseconds is
good. Tens of milliseconds will make every write slow.

**2. Configure.** Make the cluster repo and identities ("Cluster repo"
above), then:

```sh
cd deploy
export RAFT5FS_CLUSTER=~/projects/raft5fs-clusters/prod
$EDITOR $RAFT5FS_CLUSTER/cluster.conf   # nodes, IPs, names, SSH user and port, RAFT5_REPO
```

**3. Make the secrets and build.** The first run makes the CAs and signs
every certificate, so it needs the CA identity:

```sh
eval "$(./unlock --ca /media/usb/ca.age)"
./certs.sh
rustup target add x86_64-unknown-linux-musl   # once; also install musl-gcc
./build.sh
```

**4. Install every node.** The first gets the bootstrap login. Until the
cluster is bootstrapped, nothing can serve, hence `--no-check` on the
other two:

```sh
./install.sh --bootstrap node1
./install.sh --no-check node2 node3
```

Each node now has `wg0` up (check with `ping 10.10.0.2` from node1), its
firewall on, and both services installed. `raft5fs-server` keeps
restarting until step 5.

**5. Bootstrap the store.** In the admin shell, the password is
`./secrets.sh show admin.pw` and `create_user` asks for
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

`endpoints` should list all three nodes. `acl_set ""` locks every key to
the filesystem servers' account, as in SETUP.txt section 3.
`backup-operators` lets that account take and remove snapshots and
backups, so day-to-day admin never needs the store administrator.

**6. Finish.** Reinstall node1 without `--bootstrap`, which removes the
bootstrap login, then check every node:

```sh
./install.sh --all
```

The first filesystem server to start creates the filesystem, with
`CHUNK_SIZE` from `cluster.conf`.

**7. Add users** (SETUP.txt section 5):

```sh
./fsadmin.sh user add alice
```

This prints an invitation: one line holding alice's one-time code, every
server's public address and `fs-ca.pem`. It is as secret as the code, so
hand it to alice alone. On her own machine she runs:

```sh
raft5fs enrol 'raft5fs-invite:1:...'
mkdir -p ~/raft5fs && raft5fs mount ~/raft5fs
```

`enrol` saves a profile, so no command needs the servers or the CA again.

## Day to day

| Task | Command |
|---|---|
| Users | `./fsadmin.sh user add\|del\|list ...` |
| Snapshots | `./fsadmin.sh snapshot create\|del\|list ...` |
| Backups | `./fsadmin.sh backup create\|del\|list ...` (see "Backups") |
| Store admin shell | `./admin-shell.sh [node]` |
| See what an install would change | `./install.sh --dry-run --all` |
| Upgrade | `./build.sh && ./install.sh --all`, one node at a time, each checked |
| Renew certificates | `./certs.sh renew && ./install.sh --all` (needs `unlock --ca`) |
| Reboot after updates | `./reboot.sh` |
| Logs | `journalctl -u raft5-server -u raft5fs-server` on the node |
| Certificate check | `raft5fs-cert-check` on the node |

`install.sh` restarts only the services whose files changed. Changing
WireGuard peers is applied in place (`wg syncconf`). A node's own
WireGuard *address* can't be changed that way: changing it means
re-bootstrapping that node's membership, so pick the addresses once.

`./install.sh --dry-run` sends the bundle as usual but changes nothing:
it lists the files that would change (names only, never contents), and
the services that would restart. Use it before any install you're unsure
of.

## Hardening the nodes

Each node gets these whatever the settings:

- **Security updates:** they install daily (`unattended-upgrades`).
- **No automatic reboots:** a reboot outside `reboot.sh` would take a node
  down without checking the others are up. Run `./reboot.sh` now and then,
  e.g. weekly; it reboots only the nodes that need it
  (`/var/run/reboot-required`), one at a time, each checked.

The rest is set in `cluster.conf`.

**An admin user instead of root.** Root login over SSH is the first
thing attacked. Switch in three steps, so you can't lock yourself out:

1. Put your SSH public key(s) in the cluster's `authorized_keys`
   (`$RAFT5FS_CLUSTER/authorized_keys`, a plain file: public keys only).
   Set `ADMIN_USER=admin`, then `./install.sh --all`. Each node gets the
   user, your keys, and passwordless sudo.
2. Check it works on every node, e.g. `ssh admin@<node> sudo -n true`.
   Then set `SSH_USER=admin` and run `./install.sh --dry-run --all`, which
   should say nothing would change.
3. Set `SSH_HARDEN=yes` and `./install.sh --all`. SSH then takes keys
   only and refuses root. `install.sh` refuses this step while
   `SSH_USER=root`.

To undo step 3, set `SSH_HARDEN=no` and install again.

**Nightly backups.** With the backup space set up ("Backups"), set
`NIGHTLY_BACKUPS=yes` and `./install.sh --all`. Every node gets a timer
(03:00 UTC on the first node, 20 minutes later on each next one) that
does the following:

- snapshots the filesystem as `nightly-<date>`
- backs it up, then removes the snapshot
- deletes `nightly-*` backups beyond the newest `BACKUP_KEEP` (default 14)

The first node to run does the work; the others find it done, and
succeed. A failed backup fails the unit: check with `systemctl --failed`
or `journalctl -u raft5fs-nightly-backup`. Backups you take by hand under
other names are never deleted by it.

**The DigitalOcean firewall.** `ufw` on each node is one layer. A cloud
firewall in front of it is a second, and it also covers a node whose
`ufw` was turned off by mistake. Create it once in the DigitalOcean
console (Networking → Firewalls), applied to the three Droplets:

| Direction | Protocol | Port | Sources |
|---|---|---|---|
| Inbound | TCP | 22 (SSH) | All IPv4, All IPv6 |
| Inbound | TCP | 27060 (filesystem) | All IPv4, All IPv6 |
| Inbound | UDP | 51820 (WireGuard) | the three nodes' public IPs only |
| Outbound | ICMP, all TCP, all UDP | all | All IPv4, All IPv6 |

When you add a node, add its public IP to the WireGuard rule *before*
installing it, or it can't reach the others.

## Large files

Optionally, files' data past `OBJECT_FROM` (10 MiB) can go to an
S3-compatible bucket instead of the store, in objects of `OBJECT_BLOCK`
(16 MiB) each. Small files, and the start of every file, stay in the
store. The servers sign URLs for users' mounts after checking their
grants, and the mounts read and upload objects directly, so bulk data no
longer passes through the servers or the store. Everything in the bucket
is sealed by the mounts, as everything in the store is. See SETUP.txt
section 12 for how it works and what it costs.

Only files created while it is on use the bucket. Files made before keep
everything in the store, and stay readable whether it is on or off.

**1. Make a bucket and a key for it.** The servers sign every URL with
this key, so it needs reading, writing, deleting and listing, but only
under the prefix. On AWS:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::BUCKET/raft5fs/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::BUCKET",
      "Condition": { "StringLike": { "s3:prefix": "raft5fs/*" } }
    }
  ]
}
```

Keep the bucket private: there is no public access to give, and no CORS
to set up. The store must support conditional writes (`If-None-Match`),
which AWS S3 and current MinIO do. That is what stops a URL from
overwriting an object once it is there.

**2. Optionally, turn on versioning, with a lifecycle rule** that expires
noncurrent versions after a few days. Garbage collection deletes objects
nothing points at any more, and versioning is a safety net against
mistakes there. Backups (below) copy the objects they need, so they
don't depend on it.

**3. Configure.** In `cluster.conf`, set `S3_BUCKET`, `S3_ENDPOINT` and
`S3_REGION` (and `S3_PATH_STYLE=yes` for MinIO). Then put the key in
the cluster's secrets with `./secrets.sh edit s3.env`:

```sh
RAFT5FS_OBJECT_ACCESS_KEY=AKIA...
RAFT5FS_OBJECT_SECRET_KEY=...
```

For a store behind a private CA, add its certificate with
`./secrets.sh put s3-ca.pem <file>`. Users then need it too, as `object_ca` in their
profile (SETUP.txt section 12).

**4. Install:** `./install.sh --all`. The first server to start records
`OBJECT_FROM` and `OBJECT_BLOCK` for the filesystem's lifetime.

Users' machines must be able to reach `S3_ENDPOINT` directly. The nodes
need nothing new: their firewall already allows outgoing connections.
A server deletes an object as soon as a change (a rewrite, a truncate,
a removal) stops pointing at it, unless a snapshot still holds it. That
is only an attempt; what it misses (a failure, a restart mid-way) is left
for garbage collection: every server with the bucket configured also
collects garbage every `GC_INTERVAL` seconds, one at a time, and logs each
sweep (`journalctl -u raft5fs-server`).

**Choosing `OBJECT_BLOCK`.** Bigger blocks mean fewer objects, which means
fewer requests and faster garbage collection. But a block is rewritten
whole for any change inside it, and a mount buffers up to a block per file
being written. 16 MiB suits files written front to back and read back,
such as media, archives and backups. Use 4 MiB, or keep such files out of
large-file filesystems, for databases and VM images, which make small
random writes. `OBJECT_FROM` and `OBJECT_BLOCK` can't change once the
first server has used them.

## Backups

The cluster keeps three copies, which protects against a dead disk but
not against mistakes: a bad deletion or a bug is copied to every node at
once. Snapshots help with deletions, but they live on the cluster and in
the same bucket. A backup copies a snapshot to a separate bucket: the
store's contents, sealed to an operator key, and every object the
snapshot points to. Contents and names are sealed by the mounts already,
so the backup bucket sees nothing it couldn't before; the operator key
protects what the store itself holds in clear (accounts, sizes).

**1. Make a backup bucket and a key for it.** Use a different bucket
from `S3_BUCKET`, ideally in another region. The key needs reading,
writing, deleting and listing under `BACKUP_PREFIX`, as for the large
files bucket.

**2. Make the operator key pair.** The private key is the only way to
open the store contents of a backup. It goes into the cluster repo sealed
to the CA and recovery identities only, so the deploy identity, and so
the nodes, can never open it:

```sh
k=$XDG_RUNTIME_DIR/operator.key
./out/bin/raft5fs-server backup keygen $k
./secrets.sh put operator/backup.key $k
./secrets.sh put backup.pub $k.pub
shred -u $k $k.pub
```

**3. Configure.** In `cluster.conf`, set `BACKUP_BUCKET`,
`BACKUP_ENDPOINT` and `BACKUP_REGION` (and `BACKUP_PATH_STYLE=yes` for
MinIO). Put the key in the cluster's secrets with
`./secrets.sh edit backup.env`:

```sh
RAFT5FS_BACKUP_ACCESS_KEY=...
RAFT5FS_BACKUP_SECRET_KEY=...
```

For a private CA, add its certificate with
`./secrets.sh put backup-ca.pem <file>`. Then
`./install.sh --all`. The store account must be in `backup-operators`
(bootstrap step 5); on an older cluster, run
`group_add backup-operators user:raft5fs` in `./admin-shell.sh`.

**4. Back up.** Take a snapshot, then back it up under its name:

```sh
./fsadmin.sh snapshot create nightly-2026-10-23
./fsadmin.sh backup create nightly-2026-10-23
./fsadmin.sh backup list
```

Backups share objects, so each copies only what is new since the last
one. Once a backup is made, you can remove its snapshot to free what it
holds on the cluster (`./fsadmin.sh snapshot del ...`). Remove old
backups with `./fsadmin.sh backup del NAME`, which also deletes the
objects no other backup uses and cleans up after a backup that failed
part way. Only one backup job runs at a time. For a schedule, a cron job
on your machine can run the two commands in turn.

**5. Restore**, after losing the cluster or the bucket, into a cluster
installed as in steps 1 to 4 of "First deployment" (with `--bootstrap`
on node1) but not yet bootstrapped. Copy the objects back first, so
nothing is served before they are there:

```sh
./fsadmin.sh backup restore-objects nightly-2026-10-23
# On your machine, with the CA identity unlocked (eval "$(./unlock --ca ...)"):
eval "$(./secrets.sh show backup.env | sed 's/^/export /')"
./out/bin/raft5fs-server backup fetch-kv nightly-2026-10-23 store.backup \
    --backup-private-key <(./secrets.sh show operator/backup.key) \
    --backup-endpoint ... --backup-bucket ... --backup-region ...
scp store.backup node1:/root/
./admin-shell.sh node1
raft> bootstrap node1 --restore-from /root/store.backup
raft> add_server https://10.10.0.2:27052
raft> add_server https://10.10.0.3:27052
raft> quit
```

Then finish with step 6. `restore-objects` copies the backup's objects
into `S3_BUCKET` under `S3_PREFIX`, which must be what the backed-up
filesystem used. Accounts, ACLs and groups come back with the store;
snapshots don't. Delete `store.backup`, here and on node1: it holds the
store's contents in clear. **Practise this once** on a scratch cluster
before relying on it.

## Adding a node later

1. Add it to `cluster.conf`, then run `./certs.sh`. This issues its
   certificate and WireGuard key, and reissues the public certificate.
2. Update the existing nodes first, one at a time, so they have the new
   WireGuard peer: `./install.sh node1 node2 node3`.
3. Install the new node: `./install.sh --no-check node4`. It runs idle,
   since it isn't a member yet.
4. In `./admin-shell.sh`, run `add_server https://10.10.0.4:27052`.
5. Check it with `./install.sh node4`. With nothing changed, this
   reinstalls nothing; it just waits for the node to serve.

Odd cluster sizes are the useful ones: three tolerates one failure and
five tolerates two.
