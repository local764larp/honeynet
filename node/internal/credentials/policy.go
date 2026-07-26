// Package credentials decides which logins a sensor accepts.
//
// The rule is that a node behaves like a machine, not like a trap: every
// account has exactly one password, that password never changes, and no other
// string authenticates against it. Everything else in this package exists to
// make that rule produce a box attackers still get into.
//
// What this replaces, and why
//
// The obvious way to guarantee that a honeypot collects post-login behaviour is
// to authenticate unconditionally once the attacker has failed a few times.
// That is what the stock implementations do, and it is a one-connection tell:
// offer half a dozen random twenty-character strings, and if one of them opens
// a shell the host is a sensor. Anything that accepts two different passwords
// for the same account has the same problem in a subtler form -- a detection
// script only has to reconnect once to find the contradiction.
//
// So admission here is an exact match against a single derived password, and
// the door is kept open instead by drawing that password from the head of the
// same wordlists the botnets are spraying. A Mirai variant working its built-in
// list still arrives at it. A probe generating random strings never does, and
// sees an ordinary failed login.
package credentials

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"sort"
	"strings"
)

// Policy is a node's fixed credential set: one password per account.
//
// Immutable after construction, so the auth path needs no locking and cannot
// drift between connections. Two sessions probing the same node an hour apart
// see identical behaviour, which is the property the whole design turns on.
type Policy struct {
	passwords map[string]string
}

// NewPolicy derives the credential set for a node.
//
// secret must be the node's private credential secret, not its ID and not its
// personality seed. Those two are public or guessable -- the node ID appears in
// the certificate CN and the seed is fleet-management input -- and deriving
// passwords from either means anyone who learns one can compute the fleet's
// logins. Callers get this from the persisted per-node secret.
//
// accounts is the node's roster, which must agree with the /etc/passwd the
// emulated shell will serve. An account that authenticates but does not appear
// in /etc/passwd is a contradiction the attacker can read the moment the shell
// opens.
func NewPolicy(secret string, accounts []string) *Policy {
	p := &Policy{passwords: make(map[string]string, len(accounts))}

	for _, acct := range accounts {
		name := strings.ToLower(strings.TrimSpace(acct))
		if name == "" {
			continue
		}
		p.passwords[name] = derivePassword(secret, name)
	}
	return p
}

// derivePassword picks the one password for an account.
//
// Keyed by the account name as well as the secret, so two accounts on the same
// node get unrelated passwords -- deriving them from the node secret alone
// would make every account on a node share a password, which no real system
// does and which one extra guess would expose.
func derivePassword(secret, account string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("honeynet/credentials/v2:"))
	mac.Write([]byte(account))
	sum := mac.Sum(nil)

	r := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(sum[:8])))) //nolint:gosec // deterministic per-node selection, not a secret

	if weakAccounts[account] {
		return headPasswords[r.Intn(len(headPasswords))]
	}
	return tailPasswords[r.Intn(len(tailPasswords))]
}

// Accept reports whether a login authenticates.
//
// Exact match on the password. The username is folded to lower case because
// that is what the emulated shell does when it resolves the account, and the
// two have to agree; the raw form the attacker sent is recorded separately by
// the caller.
func (p *Policy) Accept(user, pass string) bool {
	want, ok := p.passwords[strings.ToLower(strings.TrimSpace(user))]
	if !ok {
		// No such account. Compare against a fixed string anyway so that the
		// unknown-user path costs the same as the wrong-password path: real
		// sshd goes to deliberate lengths to equalise these, and a sensor that
		// answers faster for nonexistent users leaks its whole account roster
		// to anyone willing to time a few hundred logins.
		hmac.Equal([]byte(pass), []byte(decoyCompare))
		return false
	}
	return hmac.Equal([]byte(pass), []byte(want))
}

// decoyCompare is length-representative padding for the unknown-account branch.
const decoyCompare = "$6$invalidsalt$invalidhashinvalidhashinvalidhash"

// Accounts lists the roster this policy was built for, sorted for stable output.
func (p *Policy) Accounts() []string {
	out := make([]string, 0, len(p.passwords))
	for name := range p.passwords {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// PasswordFor exposes an account's password.
//
// For operator tooling and tests only -- there is no path from a session to
// this. It exists because an operator occasionally needs to log into their own
// sensor, and because the fingerprint tests assert on what was derived.
func (p *Policy) PasswordFor(account string) (string, bool) {
	pw, ok := p.passwords[strings.ToLower(strings.TrimSpace(account))]
	return pw, ok
}
