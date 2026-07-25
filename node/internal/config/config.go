// Package config loads node settings from a JSON file with environment
// overrides.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the complete node configuration.
type Config struct {
	// NodeID must match the CN of the client certificate. The collector
	// rejects envelopes whose node_id disagrees with the authenticated
	// identity, so a mismatch here is a hard startup failure in production.
	NodeID string `json:"node_id"`

	// PersonalitySeed drives the fake machine identity. Any stable string
	// works; using the node ID is fine and keeps provisioning simple.
	PersonalitySeed string `json:"personality_seed"`

	SpoolPath     string `json:"spool_path"`
	SpoolMaxBytes int64  `json:"spool_max_bytes"`

	NATSURL  string `json:"nats_url"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`

	SSHAddr    string `json:"ssh_addr"`
	TelnetAddr string `json:"telnet_addr"`
	HTTPAddr   string `json:"http_addr"`
	RDPAddr    string `json:"rdp_addr"`

	// HostKeyPath holds the node's SSH host key. Generated on first start if
	// absent. It must persist -- a host key that changes every restart is a
	// glaring tell to any scanner that revisits.
	HostKeyPath string `json:"host_key_path"`

	MaxSessions        int           `json:"max_sessions"`
	MaxSessionsPerIP   int           `json:"max_sessions_per_ip"`
	SessionIdleTimeout time.Duration `json:"-"`
	SessionMaxDuration time.Duration `json:"-"`

	IdleTimeoutSec int `json:"session_idle_timeout_sec"`
	MaxDurationSec int `json:"session_max_duration_sec"`

	HeartbeatSec int `json:"heartbeat_sec"`

	// CallbackHost is the authority embedded in canary URLs served by the HTTP
	// decoys -- it must be an address an attacker's tooling can reach back on,
	// so it is the sensor's public name, not its internal one. Defaults to the
	// derived hostname, which is fine for a local run but should be set to the
	// public address in production.
	CallbackHost string `json:"callback_host"`

	LogLevel string `json:"log_level"`
}

// Default returns a configuration suitable for local development. Production
// deployments override NodeID, NATSURL and the TLS material via the
// provisioning bundle.
func Default() Config {
	return Config{
		NodeID:           "node-local",
		PersonalitySeed:  "",
		SpoolPath:        "honeynode.spool",
		SpoolMaxBytes:    256 << 20,
		NATSURL:          "nats://127.0.0.1:4222",
		SSHAddr:          ":2222",
		TelnetAddr:       ":2323",
		HTTPAddr:         ":8080",
		RDPAddr:          "",
		HostKeyPath:      "honeynode_host_key",
		MaxSessions:      256,
		MaxSessionsPerIP: 8,
		IdleTimeoutSec:   180,
		MaxDurationSec:   1800,
		HeartbeatSec:     60,
		LogLevel:         "info",
	}
}

// Load reads a config file, applies environment overrides, and validates.
// A missing file is not an error -- defaults plus environment are enough to
// start a node.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := json.Unmarshal(data, &cfg); err != nil {
				return cfg, fmt.Errorf("parse %s: %w", path, err)
			}
		case !os.IsNotExist(err):
			return cfg, fmt.Errorf("read %s: %w", path, err)
		}
	}

	applyEnv(&cfg)

	if cfg.PersonalitySeed == "" {
		cfg.PersonalitySeed = cfg.NodeID
	}
	cfg.SessionIdleTimeout = time.Duration(cfg.IdleTimeoutSec) * time.Second
	cfg.SessionMaxDuration = time.Duration(cfg.MaxDurationSec) * time.Second

	return cfg, cfg.Validate()
}

func applyEnv(cfg *Config) {
	str := func(key string, dst *string) {
		if v := os.Getenv(key); v != "" {
			*dst = v
		}
	}
	num := func(key string, dst *int) {
		if v := os.Getenv(key); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}

	str("HONEYNODE_ID", &cfg.NodeID)
	str("HONEYNODE_SEED", &cfg.PersonalitySeed)
	str("HONEYNODE_SPOOL", &cfg.SpoolPath)
	str("HONEYNODE_NATS_URL", &cfg.NATSURL)
	str("HONEYNODE_CERT", &cfg.CertFile)
	str("HONEYNODE_KEY", &cfg.KeyFile)
	str("HONEYNODE_CA", &cfg.CAFile)
	str("HONEYNODE_SSH_ADDR", &cfg.SSHAddr)
	str("HONEYNODE_TELNET_ADDR", &cfg.TelnetAddr)
	str("HONEYNODE_HTTP_ADDR", &cfg.HTTPAddr)
	str("HONEYNODE_RDP_ADDR", &cfg.RDPAddr)
	str("HONEYNODE_HOST_KEY", &cfg.HostKeyPath)
	str("HONEYNODE_CALLBACK_HOST", &cfg.CallbackHost)
	str("HONEYNODE_LOG_LEVEL", &cfg.LogLevel)
	num("HONEYNODE_MAX_SESSIONS", &cfg.MaxSessions)
	num("HONEYNODE_MAX_SESSIONS_PER_IP", &cfg.MaxSessionsPerIP)
	num("HONEYNODE_IDLE_TIMEOUT_SEC", &cfg.IdleTimeoutSec)
	num("HONEYNODE_MAX_DURATION_SEC", &cfg.MaxDurationSec)
	num("HONEYNODE_HEARTBEAT_SEC", &cfg.HeartbeatSec)
}

// Validate rejects configurations that would produce a broken or unsafe node.
func (c Config) Validate() error {
	if c.NodeID == "" {
		return fmt.Errorf("node_id is required")
	}
	if strings.ContainsAny(c.NodeID, ". *>\t\n") {
		// NATS subject tokens are dot-delimited and treat * and > as
		// wildcards. A node ID containing either would let a sensor publish
		// outside its own subject scope, defeating the per-node isolation in
		// design doc section 4.4.
		return fmt.Errorf("node_id %q must not contain '.', '*', '>' or whitespace", c.NodeID)
	}
	if c.SpoolPath == "" {
		return fmt.Errorf("spool_path is required")
	}
	if c.SSHAddr == "" && c.TelnetAddr == "" && c.HTTPAddr == "" && c.RDPAddr == "" {
		return fmt.Errorf("at least one protocol listener must be configured")
	}
	if c.MaxSessions <= 0 {
		return fmt.Errorf("max_sessions must be positive")
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return fmt.Errorf("cert_file and key_file must be set together")
	}
	return nil
}
