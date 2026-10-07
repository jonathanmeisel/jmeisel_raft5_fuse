#!/usr/bin/env bash
# Copies a node's store database off the cluster, to backups/ here (or
# DIR). The node's store is stopped for the copy -- a running database
# isn't safe to copy -- and the other two carry on meanwhile, so only do
# this with the whole cluster up. Contents and names are encrypted, so the
# copy is safe to keep off-site; the secrets/ directory never goes with it.
#
#   ./backup.sh <node> [DIR]
. "$(dirname "$0")/lib.sh"
node=${1:?usage: backup.sh <node> [DIR]}
node_field "$node" 1 >/dev/null
dir=${2:-$DEPLOY/backups}
mkdir -p "$dir"
out=$dir/$node-$(date -u +%Y%m%dT%H%M%SZ).tar.gz

healthy "$node" 10 || die "the filesystem isn't serving through $node; not stopping anything"

remote='systemctl stop raft5-server; tar -C /var/lib/raft5 -czf - db; rc=$?; systemctl start raft5-server; exit $rc'
echo "stopping raft5-server on $node for the copy"
as_root "$node" "sh -c $(printf %q "$remote")" >"$out.partial"
mv "$out.partial" "$out"
echo "wrote $out ($(du -h "$out" | cut -f1))"
healthy "$node" 60 || die "$node isn't serving again after a minute: look at it"
echo "$node is serving again"
