#!/usr/bin/env bash
# Copies a node's store database from the cluster to backups/ here (or DIR).
# The node's store stops during the copy, because a running database is not
# safe to copy. The other two nodes continue, so do this only when the whole
# cluster is up. Contents and names are encrypted, so the copy is safe to
# keep off-site. The secrets/ directory is never part of it.
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
