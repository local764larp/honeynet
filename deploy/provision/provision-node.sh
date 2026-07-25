#!/usr/bin/env bash
#
# Provisions one honeypot sensor.
#
# Run on a freshly imaged VPS as root. Idempotent: re-running upgrades the
# binary and refreshes configuration without disturbing the spool, host keys,
# or derived machine identity.
#
# Order matters. Egress containment and the administrative SSH move happen
# before the honeypot binds :22, so there is no window in which the box is
# exposed without its guardrails.

set -euo pipefail

readonly NODE_ID="${1:?usage: provision-node.sh <node-id> <collector-host> <collector-port>}"
readonly COLLECTOR_HOST="${2:?missing collector host}"
readonly COLLECTOR_PORT="${3:-4222}"

readonly ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-61022}"
readonly ADMIN_CIDR="${ADMIN_CIDR:?set ADMIN_CIDR to the operator source range, e.g. 203.0.113.0/24}"
readonly RESOLVER_IP="${RESOLVER_IP:-1.1.1.1}"

readonly USER_NAME=honeynode
readonly STATE_DIR=/var/lib/honeynode
readonly CONF_DIR=/etc/honeynode
readonly CERT_DIR="${CONF_DIR}/certs"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"

# The node ID becomes a NATS subject token and a certificate CN. A dot or a
# wildcard here would let the sensor publish outside its own subject scope,
# defeating the isolation this whole script exists to establish.
[[ "$NODE_ID" =~ ^[a-zA-Z0-9_-]+$ ]] || die "node id must match ^[a-zA-Z0-9_-]+$ (got '$NODE_ID')"

# ------------------------------------------------------------- account ----

log "creating service account"
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$USER_NAME"
fi
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "$STATE_DIR"
install -d -o root -g "$USER_NAME" -m 0750 "$CONF_DIR" "$CERT_DIR"

# --------------------------------------------------- administrative ssh ----
#
# Moved off :22 before the honeypot claims it. Done first and verified,
# because getting this wrong locks the operator out of a box that is about to
# be deliberately exposed.

log "relocating administrative sshd to port ${ADMIN_SSH_PORT}"
if ! grep -qE "^Port ${ADMIN_SSH_PORT}$" /etc/ssh/sshd_config; then
    sed -i -E 's/^#?Port .*/Port '"${ADMIN_SSH_PORT}"'/' /etc/ssh/sshd_config
    grep -qE "^Port ${ADMIN_SSH_PORT}$" /etc/ssh/sshd_config \
        || echo "Port ${ADMIN_SSH_PORT}" >> /etc/ssh/sshd_config
fi

# Password auth on the real sshd would be catastrophic on a box whose entire
# purpose is attracting credential sprays.
sed -i -E 's/^#?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i -E 's/^#?PermitRootLogin .*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

sshd -t || die "sshd config invalid; refusing to continue"
systemctl restart ssh || systemctl restart sshd

log "verifying administrative sshd is reachable on ${ADMIN_SSH_PORT}"
for _ in $(seq 1 10); do
    ss -lnt | grep -q ":${ADMIN_SSH_PORT} " && break
    sleep 1
done
ss -lnt | grep -q ":${ADMIN_SSH_PORT} " \
    || die "sshd is not listening on ${ADMIN_SSH_PORT}; aborting before exposing :22"

# ------------------------------------------------------------- egress ----

log "installing egress containment"
COLLECTOR_IP="$(getent ahostsv4 "$COLLECTOR_HOST" | awk 'NR==1{print $1}')"
[[ -n "$COLLECTOR_IP" ]] || die "could not resolve collector host '$COLLECTOR_HOST'"

sed -e "s/COLLECTOR_IP/${COLLECTOR_IP}/" \
    -e "s/COLLECTOR_PORT/${COLLECTOR_PORT}/" \
    -e "s/RESOLVER_IP/${RESOLVER_IP}/" \
    -e "s|ADMIN_CIDR|${ADMIN_CIDR}|" \
    -e "s/define admin_ssh_port = 61022/define admin_ssh_port = ${ADMIN_SSH_PORT}/" \
    "$(dirname "$0")/nftables.conf" > /etc/nftables.conf

nft -c -f /etc/nftables.conf || die "nftables ruleset invalid; refusing to continue"
systemctl enable --now nftables
nft -f /etc/nftables.conf

log "confirming egress is default-deny"
# Any reachable third party proves the ruleset did not take effect. A sensor
# with open egress can be used as a relay, so this check is a hard gate.
if timeout 5 bash -c "echo > /dev/tcp/93.184.216.34/80" 2>/dev/null; then
    die "egress to an arbitrary host succeeded; containment is NOT in effect"
fi
log "egress containment verified"

# ------------------------------------------------------------- binary ----

log "installing sensor binary"
install -o root -g root -m 0755 ./honeynode /usr/local/bin/honeynode

# -------------------------------------------------------------- certs ----

if [[ ! -f "${CERT_DIR}/node-cert.pem" ]]; then
    cat <<EOF

  Client certificate not found at ${CERT_DIR}/node-cert.pem

  Issue one on the CA host, with CN exactly '${NODE_ID}':

      ./issue-cert.sh ${NODE_ID}

  Then copy node-cert.pem, node-key.pem and ca.pem into ${CERT_DIR}.

  The CN must match the node ID: the collector rejects any envelope whose
  self-reported node_id disagrees with the authenticated certificate subject.

EOF
    die "missing client certificate"
fi
chown root:"$USER_NAME" "${CERT_DIR}"/*.pem
chmod 0640 "${CERT_DIR}"/*.pem

# ------------------------------------------------------------- config ----

log "writing configuration"
cat > "${CONF_DIR}/config.json" <<EOF
{
  "node_id": "${NODE_ID}",
  "personality_seed": "${NODE_ID}",
  "spool_path": "${STATE_DIR}/honeynode.spool",
  "spool_max_bytes": 268435456,
  "nats_url": "tls://${COLLECTOR_HOST}:${COLLECTOR_PORT}",
  "cert_file": "${CERT_DIR}/node-cert.pem",
  "key_file": "${CERT_DIR}/node-key.pem",
  "ca_file": "${CERT_DIR}/ca.pem",
  "ssh_addr": ":22",
  "telnet_addr": ":23",
  "http_addr": ":80",
  "rdp_addr": "",
  "host_key_path": "${STATE_DIR}/honeynode_host_key",
  "max_sessions": 512,
  "max_sessions_per_ip": 8,
  "session_idle_timeout_sec": 180,
  "session_max_duration_sec": 1800,
  "heartbeat_sec": 60,
  "log_level": "info"
}
EOF
chown root:"$USER_NAME" "${CONF_DIR}/config.json"
chmod 0640 "${CONF_DIR}/config.json"

# ------------------------------------------------------------ service ----

log "installing service unit"
install -o root -g root -m 0644 "$(dirname "$0")/../systemd/honeynode.service" \
    /etc/systemd/system/honeynode.service
systemctl daemon-reload
systemctl enable --now honeynode

sleep 2
systemctl is-active --quiet honeynode || {
    journalctl -u honeynode -n 40 --no-pager
    die "sensor failed to start"
}

# ------------------------------------------------------------- report ----

log "provisioned"
cat <<EOF

  node id        ${NODE_ID}
  collector      tls://${COLLECTOR_HOST}:${COLLECTOR_PORT}
  admin ssh      port ${ADMIN_SSH_PORT}, restricted to ${ADMIN_CIDR}
  honeypot       :22 (ssh), :23 (telnet), :80 (http)
  egress         default-deny, verified

  Derived machine identity:

EOF
sudo -u "$USER_NAME" /usr/local/bin/honeynode -identity -config "${CONF_DIR}/config.json" | sed 's/^/    /'

cat <<EOF

  Register this node with the collector by adding to nats-server.conf:

    {
      user: "${NODE_ID}"
      permissions: {
        publish:   { allow: ["honeynet.events.${NODE_ID}.>"] }
        subscribe: { allow: [] }
      }
    }

  then reload:  nats-server --signal reload

EOF
