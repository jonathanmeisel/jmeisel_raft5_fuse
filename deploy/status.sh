#!/usr/bin/env bash
# One look at the cluster's health, since nothing alerts yet. For each node:
# its services, failed units, a pending reboot, certificate expiry, disk,
# memory and swap, and the nightly backup timer. For the cluster: the
# newest backup and the number of snapshots. With the secrets unlocked, it
# also checks for drift (install.sh --dry-run). Exits 1 if anything needs
# attention, and lists what.
#
#   ./status.sh               every check
#   ./status.sh --no-drift    skip the drift check (it sends every bundle)
. "$(dirname "$0")/lib.sh"

drift=true
case ${1:-} in
"") ;;
--no-drift) drift=false ;;
*) die "usage: status.sh [--no-drift]" ;;
esac

# Run on each node as root. Prints key=value lines; with "cluster", also
# the cluster-wide facts, which any one node can answer. Single-quoted: it
# expands on the node, not here.
# shellcheck disable=SC2016
probe='
echo "services=$(systemctl is-active raft5-server raft5fs-server | paste -sd/)"
echo "failed=$(systemctl --failed --no-legend --plain | awk "{print \$1}" | paste -sd" ")"
[ -f /var/run/reboot-required ] && echo reboot=yes || echo reboot=no
min=
for pem in /etc/raft5/*.pem /etc/raft5fs/*.pem; do
    [ -f "$pem" ] || continue
    end=$(openssl x509 -in "$pem" -noout -enddate | cut -d= -f2)
    days=$(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
    if [ -z "$min" ] || [ "$days" -lt "$min" ]; then min=$days; fi
done
echo "certdays=$min"
echo "disk=$(df --output=pcent / | tail -1 | tr -d " %")"
echo "memfree=$(awk "/MemAvailable/ {print int(\$2 / 1024)}" /proc/meminfo)"
echo "swap=$(awk "/SwapTotal/ {print int(\$2 / 1024)}" /proc/meminfo)"
echo "nightly=$(systemctl is-enabled raft5fs-nightly-backup.timer 2>/dev/null || echo off)"
echo "nightlyresult=$(systemctl show -p Result --value raft5fs-nightly-backup.service)"
if [ "${1:-}" = cluster ]; then
    if snaps=$(/usr/local/sbin/raft5fs-admin snapshot list 2>/dev/null); then
        echo "snapshots=$(printf "%s\n" "$snaps" | grep -c .)"
    else
        echo "snapshots=?"
    fi
    if [ -f /etc/raft5fs/backup.env ]; then
        if list=$(/usr/local/sbin/raft5fs-admin backup list 2>/dev/null); then
            echo "backups=$(printf "%s\n" "$list" | grep -c .)"
            echo "newest=$(printf "%s\n" "$list" | sort -t "	" -k2 -n | tail -1 | cut -f1,2)"
        else
            echo "backups=?"
        fi
    else
        echo "backups=none"
    fi
fi
'

problems=()
problem() { problems+=("$1"); }

# Facts from one node, as an associative array named by $1.
declare -A f
cluster_seen=false

for node in $(node_names); do
    want=""
    $cluster_seen || want=cluster
    if ! out=$(as_root "$node" sh -s "$want" <<<"$probe" 2>/dev/null); then
        printf '%-8s UNREACHABLE\n' "$node"
        problem "$node: can't reach it over SSH"
        continue
    fi
    f=()
    while IFS='=' read -r k v; do f[$k]=$v; done <<<"$out"

    notes=()
    before=${#problems[@]}
    [[ ${f[services]} == active/active ]] || problem "$node: services ${f[services]}"
    [[ -z ${f[failed]} ]] || problem "$node: failed units: ${f[failed]}"
    [[ ${f[reboot]} == no ]] || problem "$node: needs a reboot (./reboot.sh)"
    if [[ -n ${f[certdays]} ]] && ((f[certdays] < 30)); then
        problem "$node: a certificate expires in ${f[certdays]} days (README \"Rotating certificates\")"
    fi
    ((f[disk] < 80)) || problem "$node: disk ${f[disk]}% full"
    ((f[memfree] >= 150)) || notes+=("low memory")
    ((f[swap] > 0)) || notes+=("no swap")
    if [[ ${NIGHTLY_BACKUPS:-no} == yes ]]; then
        [[ ${f[nightly]} == enabled ]] || problem "$node: nightly backup timer is ${f[nightly]}"
        [[ ${f[nightlyresult]} == success ]] ||
            problem "$node: last nightly backup run: ${f[nightlyresult]} (journalctl -u raft5fs-nightly-backup)"
    fi
    printf '%-8s %-6s services %-13s disk %3s%%  mem %4sM free  swap %4sM  certs %sd  reboot %-3s  nightly %s%s\n' \
        "$node" "$([[ ${#problems[@]} -eq "$before" ]] && echo ok || echo CHECK)" "${f[services]}" "${f[disk]}" \
        "${f[memfree]}" "${f[swap]}" "${f[certdays]:-?}" "${f[reboot]}" "${f[nightly]}" \
        "${notes[*]:+  (${notes[*]})}"

    if [[ $want == cluster ]]; then
        cluster_seen=true
        cluster=("${f[snapshots]}" "${f[backups]}" "${f[newest]:-}")
    fi
done

echo
if $cluster_seen; then
    snapshots=${cluster[0]} backups=${cluster[1]} newest=${cluster[2]}
    if [[ $snapshots == "?" ]]; then
        problem "can't list snapshots"
    else
        echo "snapshots: $snapshots of 32"
        ((snapshots < 28)) || problem "$snapshots snapshots: the store holds at most 32"
    fi
    case $backups in
    none) echo "backups:   no backup space set up" ;;
    "?") problem "can't list backups (check the backup space's credentials)" ;;
    0) echo "backups:   none"
       [[ ${NIGHTLY_BACKUPS:-no} != yes ]] || problem "no backups, though nightly backups are on" ;;
    *)
        name=${newest%%$'\t'*} made=${newest##*$'\t'}
        age=$((($(date +%s) - made) / 3600))
        echo "backups:   $backups, newest $name (${age}h ago)"
        if [[ ${NIGHTLY_BACKUPS:-no} == yes ]] && ((age > 36)); then
            problem "the newest backup is ${age}h old"
        fi
        ;;
    esac
fi

if $drift; then
    if [[ -z ${SOPS_AGE_KEY:-}${SOPS_AGE_KEY_FILE:-} ]]; then
        echo "drift:     not checked (eval \"\$(./unlock)\" first, or --no-drift)"
    else
        changes=$("$DEPLOY/install.sh" --dry-run --all 2>&1 | grep -E '\] would ' || true)
        if [[ -z $changes ]]; then
            echo "drift:     none"
        else
            echo "drift:     nodes differ from the cluster repo:"
            # shellcheck disable=SC2001
            sed 's/^/           /' <<<"$changes"
            problem "drift: run ./install.sh --dry-run --all, then ./install.sh --all"
        fi
    fi
fi

echo
if ((${#problems[@]} == 0)); then
    echo "all good"
else
    echo "needs attention:"
    printf '  - %s\n' "${problems[@]}"
    exit 1
fi
