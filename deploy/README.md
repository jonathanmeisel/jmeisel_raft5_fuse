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
`wireguard-tools` package), Rust, and a checkout of the raft5 store's
repository.

## What's here

| File | What it does |
|---|---|
| `cluster.conf.example` | The cluster's layout: nodes, addresses, ports. Copy it to `cluster.conf` and edit. |
| `certs.sh` | Makes every secret: two CAs, certificates, WireGuard keys, shared secrets and passwords, all into `secrets/`. `certs.sh renew` reissues the certificates. |
| `build.sh` | Builds static (musl) binaries into `out/bin`. |
| `render.sh` | Assembles each node's bundle into `out/<node>/`. `install.sh` runs it for you. |
| `install.sh` | Installs or upgrades nodes over SSH, one at a time, checking each is serving before moving on. |
| `admin-shell.sh` | Opens the store's admin shell (`raft`) on a node. |
| `fsadmin.sh` | Manages users and snapshots: `user add/del/list`, `snapshot create/del/list`. |
| `backup.sh` | Copies a node's store database off the cluster. |
| `templates/` | The systemd units, the scripts installed on the nodes, and the node-side installer. |

`cluster.conf`, `secrets/`, `out/` and `backups/` are git-ignored. With
large files in a bucket (below), `secrets/s3.env` holds its credentials.
**`secrets/` is the only copy of the CA keys and passwords: back it up
somewhere safe and offline.**

## The certificates

There are two CAs, kept apart:

- **internal-ca** is the store's own. Each node gets one certificate for
  its WireGuard address, which it uses in three roles:
  - as a store node, for peer mTLS and client mTLS;
  - as the filesystem server logging in to the store;
  - for the admin shell.

  Nothing outside the cluster ever needs this CA.
- **fs-ca** covers the filesystem servers' public port. One certificate
  covers every node's public name and IP. Users get `secrets/fs-ca.pem`
  and mount with `--ca fs-ca.pem`.

Certificates last `CERT_DAYS` (default 397). The CAs last ten years.
Each node runs a daily check, `raft5fs-cert-check.timer`, that fails
(visible in `systemctl --failed` and the journal) once any certificate is
within 30 days of expiring. Both servers read their certificates only at
startup, so renewing means reinstalling, which restarts them one node at
a time:

```sh
./certs.sh renew
./install.sh --all
```

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

**2. Configure:**

```sh
cd deploy
cp cluster.conf.example cluster.conf
$EDITOR cluster.conf         # nodes, IPs, names, SSH user and port, RAFT5_REPO
```

**3. Make the secrets and build:**

```sh
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
`secrets/admin.pw` and `create_user` asks for `secrets/store.pw`:

```sh
./admin-shell.sh node1
raft> bootstrap node1
raft> add_server https://10.10.0.2:27052
raft> add_server https://10.10.0.3:27052
raft> endpoints
raft> create_user raft5fs
raft> acl_set "" user:raft5fs=write
raft> quit
```

`endpoints` should list all three nodes. `acl_set ""` locks every key to
the filesystem servers' account, as in SETUP.txt section 3.

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
| Snapshots | `./fsadmin.sh snapshot create\|del\|list ...` (asks for `secrets/admin.pw`) |
| Store admin shell | `./admin-shell.sh [node]` |
| Upgrade | `./build.sh && ./install.sh --all`, one node at a time, each checked |
| Renew certificates | `./certs.sh renew && ./install.sh --all` |
| Logs | `journalctl -u raft5-server -u raft5fs-server` on the node |
| Certificate check | `raft5fs-cert-check` on the node |

`install.sh` restarts only the services whose files changed. Changing
WireGuard peers is applied in place (`wg syncconf`). A node's own
WireGuard *address* can't be changed that way: changing it means
re-bootstrapping that node's membership, so pick the addresses once.

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

**2. Turn on versioning, with a lifecycle rule** that expires noncurrent
versions after at least as long as you keep backups (below). Garbage
collection deletes objects nothing points at any more. A restored backup
may point at some of them again, and versioning is what still has them.

**3. Configure.** In `cluster.conf`, set `S3_BUCKET`, `S3_ENDPOINT` and
`S3_REGION` (and `S3_PATH_STYLE=yes` for MinIO). Then put the key in
`secrets/s3.env`:

```sh
RAFT5FS_OBJECT_ACCESS_KEY=AKIA...
RAFT5FS_OBJECT_SECRET_KEY=...
```

For a store behind a private CA, put its certificate in
`secrets/s3-ca.pem`. Users then need it too, as `object_ca` in their
profile (SETUP.txt section 12).

**4. Install:** `./install.sh --all`. The first server to start records
`OBJECT_FROM` and `OBJECT_BLOCK` for the filesystem's lifetime.

Users' machines must be able to reach `S3_ENDPOINT` directly. The nodes
need nothing new: their firewall already allows outgoing connections.
Every server with the bucket configured also collects garbage every
`GC_INTERVAL` seconds, one at a time, and logs each sweep
(`journalctl -u raft5fs-server`).

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
once. Snapshots help with deletions, but they live on the same cluster.
So also copy the store off it regularly:

```sh
./backup.sh node3                 # to backups/node3-<time>.tar.gz
```

This stops that node's store for the duration of the copy while the
other two carry on. Run it only with the whole cluster healthy (the
script checks first). The copy holds only what the servers can see, so
it's fine to keep it off-site, for example in object storage. It
doesn't include the bucket's objects (see "Large files"): the bucket's
versioning is what keeps those restorable. Keep
`secrets/` separately, offline. With the copy alone, nobody can log in.

**Restoring is untested.** A store database records the cluster's
membership and its node's place in it. Before relying on these backups,
practise restoring one into a scratch cluster of three nodes with the
same names.

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
