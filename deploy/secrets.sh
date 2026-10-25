#!/usr/bin/env bash
# Looks after the cluster repo's secrets (README "Secrets"). Secret
# files are kept only sops-encrypted, as secrets/<path>.sops; certificates
# and public keys are kept as they are. Every command but `init` needs
# RAFT5FS_CLUSTER, and every command that reads a secret needs
# eval "$(./unlock)" first.
#
#   ./secrets.sh init <repo> <cluster> --deploy <age1...> --ca <age1...> --recovery <age1...>
#                           make a new cluster repo: .sops.yaml, hooks,
#                           .gitignore, and an empty <repo>/<cluster>/
#   ./secrets.sh import <dir>
#                           copy a plaintext secrets directory in,
#                           encrypting the secret files; skips what exists
#   ./secrets.sh put <path> <file>
#                           add or replace one file, e.g.
#                           put operator/backup.key ~/offline/raft5fs-backup.key
#   ./secrets.sh show <path>
#                           print one file, e.g. show admin.pw
#   ./secrets.sh edit <path>
#                           edit one file in $EDITOR (made if missing)
#   ./secrets.sh check      every secret is encrypted and opens; nothing
#                           plaintext is staged in git
#   ./secrets.sh updatekeys re-encrypt every secret to the recipients in
#                           .sops.yaml, after adding or removing an identity
#
# <path> is relative to the cluster's secrets/ and has no .sops suffix.
set -euo pipefail

init() {
    local repo=${1:?} cluster=${2:?} deploy='' ca='' recovery=''
    shift 2
    while (($#)); do
        case $1 in
        --deploy) deploy=$2 ;;
        --ca) ca=$2 ;;
        --recovery) recovery=$2 ;;
        *) echo "secrets.sh: unknown option $1" >&2 && exit 1 ;;
        esac
        shift 2
    done
    for key in "$deploy" "$ca" "$recovery"; do
        [[ $key == age1* ]] || { echo "secrets.sh: init needs --deploy, --ca and --recovery age public keys" >&2 && exit 1; }
    done
    [[ ! -e $repo/.sops.yaml ]] || { echo "secrets.sh: $repo already has a .sops.yaml" >&2 && exit 1; }
    mkdir -p "$repo/.githooks" "$repo/$cluster/secrets"
    cat >"$repo/.sops.yaml" <<EOF
# Who can open each secret. The first rule that matches wins.
#   deploy    $deploy
#   CA        $ca
#   recovery  $recovery
creation_rules:
  # The CA keys and the operator backup key: the offline CA identity (and
  # recovery), never the deploy identity.
  - path_regex: secrets/(internal-ca\.key|fs-ca\.key|operator/.*)\.sops$
    age: $ca,$recovery
  # Everything else: everyday deploys.
  - path_regex: secrets/.*\.sops$
    age: $deploy,$recovery
EOF
    cat >"$repo/.gitignore" <<'EOF'
# Plaintext secrets must never be committed; only their .sops files.
*.key
*.pw
*.secret
*.env
*.partial
EOF
    cat >"$repo/.githooks/pre-commit" <<'EOF'
#!/bin/sh
# Refuses a commit that would add a plaintext secret, or a .sops file that
# isn't actually encrypted.
status=0
for f in $(git diff --cached --name-only --diff-filter=ACMR); do
    case $f in
    *.key | *.pw | *.secret | *.env)
        echo "pre-commit: $f is a plaintext secret; add it with deploy/secrets.sh" >&2
        status=1
        ;;
    *.sops)
        if ! git show ":$f" | grep -q '"sops"'; then
            echo "pre-commit: $f isn't sops-encrypted" >&2
            status=1
        fi
        ;;
    esac
done
exit $status
EOF
    chmod 755 "$repo/.githooks/pre-commit"
    cat >"$repo/README.md" <<EOF
# raft5fs clusters

One directory per cluster, used by the raft5fs repo's deploy/ scripts with
RAFT5FS_CLUSTER=<this repo>/<cluster>. Secrets are sops-encrypted with age;
see .sops.yaml for who can open what, and the raft5fs deploy README
("Cluster repo") for how to use it.
EOF
    if [[ ! -d $repo/.git ]]; then
        git -C "$repo" init -q
    fi
    git -C "$repo" config core.hooksPath .githooks
    echo "made $repo with cluster $cluster. Next: copy cluster.conf into $repo/$cluster/."
}

if [[ ${1:-} == init ]]; then
    shift
    init "$@"
    exit
fi

. "$(dirname "$0")/lib.sh"

# The plaintext of path $1, on stdout.
show() {
    local rel=$1
    if [[ -f $STORE/$rel.sops ]]; then
        if ! sops_decrypt "secrets/$rel.sops" 2>/dev/null; then
            needs_ca_identity "$rel" &&
                die "secrets/$rel opens only with the CA identity: eval \"\$(./unlock --ca <file>)\""
            die "cannot decrypt secrets/$rel with the unlocked identities"
        fi
    elif [[ -f $STORE/$rel ]]; then
        cat "$STORE/$rel"
    else
        die "no secrets/$rel"
    fi
}

# Writes stdin as path $1: encrypted if it is a secret.
put() {
    local rel=$1
    if is_secret "$rel"; then
        sops_encrypt "$rel"
        echo "sealed secrets/$rel.sops" >&2
    else
        mkdir -p "$(dirname "$STORE/$rel")"
        cat >"$STORE/$rel"
        echo "wrote secrets/$rel" >&2
    fi
}

case ${1:-} in
import)
    from=${2:?usage: secrets.sh import <dir>}
    [[ -d $from ]] || die "no directory $from"
    mkdir -p "$STORE"
    while IFS= read -r rel; do
        if is_secret "$rel"; then dest=$STORE/$rel.sops; else dest=$STORE/$rel; fi
        if [[ -f $dest ]]; then
            echo "kept secrets/$rel" >&2
            continue
        fi
        put "$rel" <"$from/$rel"
    done < <(cd "$from" && find . -type f | sed 's|^\./||' | sort)
    ;;
put)
    rel=${2:?usage: secrets.sh put <path> <file>}
    file=${3:?usage: secrets.sh put <path> <file>}
    put "$rel" <"$file"
    ;;
show)
    show "${2:?usage: secrets.sh show <path>}"
    ;;
edit)
    rel=${2:?usage: secrets.sh edit <path>}
    work=$(mktemp -d -p "${XDG_RUNTIME_DIR:-/dev/shm}" raft5fs-edit.XXXXXX)
    trap 'rm -rf "$work"' EXIT
    file=$work/$(basename "$rel")
    if [[ -f $STORE/$rel.sops || -f $STORE/$rel ]]; then
        show "$rel" >"$file"
    else
        : >"$file"
    fi
    before=$(sha256sum <"$file")
    # Split like git does, so EDITOR="code --wait" works.
    # shellcheck disable=SC2086
    ${EDITOR:-vi} "$file"
    if [[ $(sha256sum <"$file") == "$before" ]]; then
        echo "unchanged" >&2
    else
        put "$rel" <"$file"
    fi
    ;;
check)
    status=0
    while IFS= read -r rel; do
        if [[ $rel == *.sops ]]; then
            if ! sops_decrypt "secrets/$rel" >/dev/null 2>&1; then
                if needs_ca_identity "${rel%.sops}"; then
                    echo "locked: secrets/$rel (opens with the CA identity)"
                else
                    echo "FAIL: secrets/$rel doesn't open with the unlocked identities"
                    status=1
                fi
            fi
        elif is_secret "$rel"; then
            echo "FAIL: secrets/$rel is a plaintext secret"
            status=1
        fi
    done < <(cd "$STORE" && find . -type f | sed 's|^\./||' | sort)
    staged=$(git -C "$CLUSTER" diff --cached --name-only 2>/dev/null |
        grep -E '\.(key|pw|secret|env)$' || true)
    if [[ -n $staged ]]; then
        echo "FAIL: plaintext secrets are staged in git: $staged"
        status=1
    fi
    ((status == 0)) && echo "every secret is encrypted and opens (or needs the CA identity)"
    exit $status
    ;;
updatekeys)
    while IFS= read -r rel; do
        (cd "$CLUSTER" && sops updatekeys --yes --input-type json "secrets/$rel")
    done < <(cd "$STORE" && find . -type f -name '*.sops' | sed 's|^\./||' | sort)
    ;;
*)
    sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
    ;;
esac
