package credentials

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// secretBytes is the entropy behind a node's credential set. Thirty-two bytes
// because the secret keys an HMAC and there is no reason to be shorter.
const secretBytes = 32

// LoadOrCreateSecret returns the node's credential secret, generating and
// persisting one on first start.
//
// This is deliberately not derived from the node ID or the personality seed.
// Both of those are provisioning inputs: the ID appears in the client
// certificate CN and travels with every envelope, and the seed is chosen by
// whoever deploys the fleet, often as a predictable function of the ID. Deriving
// logins from either means that anyone who learns one node's identity -- which
// is public information the moment the sensor answers a connection -- can
// compute the credentials of every sensor in the fleet.
//
// Persisting matters for the same reason the host key is persisted. A node
// whose passwords changed on restart would be a machine whose passwords changed
// on restart, and the scanners that sweep the same ranges continuously would
// see it.
func LoadOrCreateSecret(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("credential secret path is required")
	}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		secret := strings.TrimSpace(string(data))
		if len(secret) < 2*secretBytes {
			return "", fmt.Errorf("credential secret %s is too short (%d chars); "+
				"remove it to have a new one generated", path, len(secret))
		}
		return secret, nil

	case os.IsNotExist(err):
		buf := make([]byte, secretBytes)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generate credential secret: %w", err)
		}
		secret := hex.EncodeToString(buf)

		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return "", fmt.Errorf("create secret directory %s: %w", dir, err)
			}
		}
		// 0600: the secret is equivalent to the node's password list.
		if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
			return "", fmt.Errorf("write credential secret %s: %w", path, err)
		}
		return secret, nil

	default:
		return "", fmt.Errorf("read credential secret %s: %w", path, err)
	}
}

// AccountsFrom projects a personality's user roster onto the account list a
// Policy is built from.
//
// Taking the roster from the personality rather than from a list of our own is
// what keeps the credential set and /etc/passwd from disagreeing. The shell
// serves that same roster, so an account that authenticates is an account the
// attacker can then see, and one that does not exist never authenticates.
func AccountsFrom(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, n := range names {
		name := strings.ToLower(strings.TrimSpace(n))
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}
