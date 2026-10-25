#!/usr/bin/env bash
# Prints the web app's config (README "Web app"), as one line of JSON for
# the raft5fs repo's WEB_CONFIG variable on GitHub: every cluster in the
# cluster repo with the web app on (WEB_ORIGIN set), so one app serves
# them all. It reads only cluster.conf and the public fs-ca.pem, so it
# needs no unlocking.
#
#   ./webapp-config.sh                  every cluster beside RAFT5FS_CLUSTER
#   ./webapp-config.sh <cluster dir>... just these
#
# Each filesystem is named after its cluster's directory, which is what
# the app's login screen shows.
set -euo pipefail

die() {
    echo "$(basename "$0"): $*" >&2
    exit 1
}

if (($# == 0)); then
    [[ -n ${RAFT5FS_CLUSTER:-} ]] ||
        die "set RAFT5FS_CLUSTER to a cluster's directory, or name the directories"
    parent=$(cd "$RAFT5FS_CLUSTER/.." && pwd)
    for dir in "$parent"/*/; do
        [[ -f $dir/cluster.conf ]] && set -- "$@" "${dir%/}"
    done
fi

# The origin (scheme://host[:port]) of URL $1.
origin() {
    local rest=${1#*://}
    echo "${1%%://*}://${rest%%/*}"
}

# Cluster directory $1's WEB_ORIGIN and its filesystem's entry, separated
# by a tab, or nothing if its web app is off. Run it in a subshell: it
# reads the cluster's settings into the shell.
entry() {
    local dir=$1 name servers="" node fs_id objects=""
    name=$(basename "$dir")
    [[ $name =~ ^[A-Za-z0-9._-]+$ ]] || die "$dir: name the directory with letters, digits, '.', '_' and '-' only"
    # shellcheck source=cluster.conf.example
    . "$dir/cluster.conf"
    [[ -n ${WEB_ORIGIN:-} ]] || return 0
    while read -r node _ _ public_name; do
        [[ -n $node ]] || continue
        [[ -n ${public_name:-} && $public_name != - ]] || die "$name: $node has no DNS name in NODES"
        servers+="${servers:+,}\"https://$public_name:${WEB_PORT:-27061}\""
    done <<<"$NODES"
    [[ -f $dir/secrets/fs-ca.pem ]] || die "$name: no secrets/fs-ca.pem (run ./certs.sh)"
    fs_id=$(openssl x509 -in "$dir/secrets/fs-ca.pem" -outform der | sha256sum | cut -c1-16)
    # Where the servers' signed URLs for blocks point.
    if [[ -n ${S3_BUCKET:-} ]]; then
        if [[ ${S3_PATH_STYLE:-no} == yes ]]; then
            objects=$(origin "$S3_ENDPOINT")
        else
            local scheme=${S3_ENDPOINT%%://*} host
            host=$(origin "$S3_ENDPOINT")
            objects="$scheme://$S3_BUCKET.${host#*://}"
        fi
        objects=",\"objects\":\"$objects\""
    fi
    printf '%s\t{"name":"%s","servers":[%s]%s,"fsId":"%s"}\n' \
        "$WEB_ORIGIN" "$name" "$servers" "$objects" "$fs_id"
}

entries="" origins=""
for dir in "$@"; do
    [[ -f $dir/cluster.conf ]] || die "no cluster.conf in $dir"
    # In a subshell, so the clusters' settings don't mix.
    line=$(entry "$dir")
    [[ -n $line ]] || continue
    entries+="${entries:+,}${line#*$'\t'}"
    origins+="${line%%$'\t'*}"$'\n'
done
[[ -n $entries ]] || die "no cluster has the web app on (WEB_ORIGIN in cluster.conf)"
if (($(sort -u <<<"${origins%$'\n'}" | wc -l) > 1)); then
    echo "warning: the clusters' WEB_ORIGINs differ; one app has one origin, so set them all to it:" >&2
    sort -u <<<"${origins%$'\n'}" | sed 's/^/  /' >&2
fi
echo "{\"filesystems\":[$entries]}"
