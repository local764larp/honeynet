#!/usr/bin/env bash
#
# Issues a client certificate for one sensor.
#
# Run on the CA host, which must not be a sensor. The CA private key is the
# single credential that would let an attacker impersonate any node in the
# fleet; keeping it off internet-exposed infrastructure is the whole point.
#
#   ./issue-cert.sh <node-id>
#
# The CN is set to the node ID because the collector cross-checks it against
# every envelope's self-reported node_id. That check is what stops a
# compromised sensor from attributing its output to a peer.

set -euo pipefail

readonly NODE_ID="${1:?usage: issue-cert.sh <node-id>}"
readonly CA_DIR="${CA_DIR:-./ca}"
readonly OUT_DIR="${OUT_DIR:-./certs/${NODE_ID}}"
readonly DAYS="${DAYS:-365}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$NODE_ID" =~ ^[a-zA-Z0-9_-]+$ ]] \
    || die "node id must match ^[a-zA-Z0-9_-]+$ (it becomes a NATS subject token)"

mkdir -p "$CA_DIR" "$OUT_DIR"

# ------------------------------------------------------------------ CA ----

if [[ ! -f "${CA_DIR}/ca-key.pem" ]]; then
    log "creating certificate authority"
    openssl ecparam -name prime256v1 -genkey -noout -out "${CA_DIR}/ca-key.pem"
    chmod 0400 "${CA_DIR}/ca-key.pem"

    openssl req -x509 -new -nodes \
        -key "${CA_DIR}/ca-key.pem" \
        -sha256 -days 3650 \
        -subj "/O=Honeynet/CN=Honeynet Sensor CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "${CA_DIR}/ca.pem"

    log "CA created at ${CA_DIR}/ca.pem"
    printf '\033[1;33m    Keep ca-key.pem off every sensor. It can mint any node identity.\033[0m\n'
fi

# -------------------------------------------------------------- sensor ----

log "issuing certificate for ${NODE_ID}"

openssl ecparam -name prime256v1 -genkey -noout -out "${OUT_DIR}/node-key.pem"
chmod 0400 "${OUT_DIR}/node-key.pem"

openssl req -new \
    -key "${OUT_DIR}/node-key.pem" \
    -subj "/O=Honeynet/CN=${NODE_ID}" \
    -out "${OUT_DIR}/node.csr"

# clientAuth only. A sensor certificate must never be usable to stand up
# something that impersonates the collector.
cat > "${OUT_DIR}/ext.cnf" <<EOF
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName   = DNS:${NODE_ID}
EOF

openssl x509 -req \
    -in "${OUT_DIR}/node.csr" \
    -CA "${CA_DIR}/ca.pem" \
    -CAkey "${CA_DIR}/ca-key.pem" \
    -CAcreateserial \
    -days "$DAYS" -sha256 \
    -extfile "${OUT_DIR}/ext.cnf" \
    -out "${OUT_DIR}/node-cert.pem"

rm -f "${OUT_DIR}/node.csr" "${OUT_DIR}/ext.cnf"
cp "${CA_DIR}/ca.pem" "${OUT_DIR}/ca.pem"

# Verify the CN came out exactly right; a mismatch means every envelope this
# sensor publishes will be rejected, and that is far cheaper to catch here.
actual_cn="$(openssl x509 -in "${OUT_DIR}/node-cert.pem" -noout -subject \
             | sed -n 's/.*CN *= *\([^,]*\).*/\1/p' | tr -d ' ')"
[[ "$actual_cn" == "$NODE_ID" ]] \
    || die "certificate CN is '${actual_cn}', expected '${NODE_ID}'"

log "issued"
cat <<EOF

  CN            ${actual_cn}
  valid         ${DAYS} days
  files         ${OUT_DIR}/node-cert.pem
                ${OUT_DIR}/node-key.pem
                ${OUT_DIR}/ca.pem

  Copy all three to /etc/honeynode/certs/ on the sensor, then add its NATS
  permission block and reload the server.

EOF
