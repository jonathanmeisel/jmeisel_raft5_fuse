#!/usr/bin/env bash
# Makes all the secrets that the cluster needs, in the cluster repo's
# secrets/ (RAFT5FS_CLUSTER). Secret files are written sops-encrypted;
# certificates and public keys as they are. Commit and push the cluster
# repo after.
#
#   ./certs.sh          make whatever is missing: both CAs, every
#                       certificate, the WireGuard keys, the shared secrets
#                       and the passwords. Safe to run again, e.g. after
#                       adding a node to cluster.conf.
#                       Signing a certificate needs the CA identity:
#                       eval "$(./unlock --ca <file>)" first.
#   ./certs.sh renew    issue every certificate again (the CAs stay), for
#                       renewal or after the nodes' names or addresses
#                       changed. Then install.sh each node, one at a time.
#
# Two separate CAs:
#   internal-ca  the store's: its nodes' peer and client mTLS. Only the
#                servers ever see it. Each node has one certificate, for
#                its WireGuard address, used as the store node, as the
#                filesystem server logging in to the store, and by the
#                admin shell.
#   fs-ca        the filesystem servers' public port. Users get fs-ca.pem,
#                to mount with (--ca); one certificate covers every
#                server's public name and address.
. "$(dirname "$0")/lib.sh"

renew=false
case ${1:-} in
"") ;;
renew) renew=true ;;
*) die "usage: certs.sh [renew]" ;;
esac

command -v openssl >/dev/null || die "openssl isn't installed"
command -v wg >/dev/null || die "wg isn't installed (the wireguard-tools package)"

umask 077
mkdir -p "$STORE"
open_secrets
mkdir -p "$SECRETS/nodes" "$SECRETS/wg"

# A path for messages: relative to secrets/, not the temporary directory.
shown() {
    echo "secrets/${1#"$SECRETS"/}"
}

# A random secret, written one time.
secret() {
    local file=$1 bytes=$2
    [[ -f $file ]] && return
    head -c "$bytes" /dev/urandom | base64 -w0 >"$file"
    echo "made $(shown "$file")"
}

# A self-signed CA, made one time.
ca() {
    local name=$1 cn=$2
    [[ -f $SECRETS/$name.pem ]] && return
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -days 3650 -subj "/CN=$cn" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$SECRETS/$name.key" -out "$SECRETS/$name.pem" 2>/dev/null
    echo "made $(shown "$SECRETS/$name.pem")"
}

# A certificate $out.pem / $out.key from CA $ca, for subjectAltName $san and
# extended key usage $eku. Skipped if it exists and this is not a renewal.
leaf() {
    local out=$1 ca=$2 cn=$3 san=$4 eku=$5
    if [[ -f $out.pem ]] && ! $renew; then return; fi
    [[ -f $SECRETS/$ca.key ]] ||
        die "issuing $(shown "$out.pem") needs the CA identity: eval \"\$(./unlock --ca <file>)\""
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -subj "/CN=$cn" -keyout "$out.key" -out "$out.csr" 2>/dev/null
    printf '%s\n' \
        'basicConstraints=critical,CA:FALSE' \
        'keyUsage=critical,digitalSignature' \
        "extendedKeyUsage=$eku" \
        "subjectAltName=$san" >"$out.ext"
    openssl x509 -req -in "$out.csr" -CA "$SECRETS/$ca.pem" -CAkey "$SECRETS/$ca.key" \
        -CAcreateserial -days "$CERT_DAYS" -extfile "$out.ext" -out "$out.pem" 2>/dev/null
    rm -f "$out.csr" "$out.ext"
    echo "issued $(shown "$out.pem") ($san)"
}

ca internal-ca "raft5fs internal CA"
ca fs-ca "raft5fs CA"

# The store's token-signing secret, and the filesystem servers' session key.
# Each one is the same on every node.
secret "$SECRETS/jwt.secret" 48
secret "$SECRETS/token.key" 48
# Passwords for the store's administrator and the filesystem servers' store
# account.
secret "$SECRETS/admin.pw" 24
secret "$SECRETS/store.pw" 24

fs_san=()
while read -r name public_ip wg_ip public_name; do
    leaf "$SECRETS/nodes/$name" internal-ca "$name" "IP:$wg_ip" serverAuth,clientAuth
    [[ $public_name != - ]] && fs_san+=("DNS:$public_name")
    fs_san+=("IP:$public_ip")
    if [[ ! -f $SECRETS/wg/$name.key ]]; then
        wg genkey >"$SECRETS/wg/$name.key"
        echo "made WireGuard key for $name"
    fi
    wg pubkey <"$SECRETS/wg/$name.key" >"$SECRETS/wg/$name.pub"
done < <(nodes)

san=$(IFS=,; echo "${fs_san[*]}")
# Also issue it again when the nodes' public names or addresses change.
if [[ $(cat "$SECRETS/fs.san" 2>/dev/null) != "$san" ]]; then
    rm -f "$SECRETS/fs.pem"
fi
leaf "$SECRETS/fs" fs-ca raft5fs "$san" serverAuth
echo "$san" >"$SECRETS/fs.san"

seal_secrets
echo
if ((SEALED)); then
    echo "commit and push the cluster repo ($CLUSTER)."
else
    echo "nothing to make or renew."
fi
echo "users mount with --ca fs-ca.pem: $STORE/fs-ca.pem"
