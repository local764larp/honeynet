package sshd

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"strings"
)

// acceptCredential decides whether an offered credential authenticates.
//
// Two mechanisms, and the tension between them is the point:
//
//   - A per-node accepted set, derived from the personality seed. Which
//     credential works is itself intelligence -- it tells us which wordlist
//     entry the actor believed in -- and deriving the set per node stops the
//     fleet from being fingerprinted by "the box that accepts root:root".
//
//   - An unconditional grant after a few failures. A sensor that never lets
//     anyone in observes credential sprays and nothing else. The payload,
//     the infrastructure, the tooling -- everything downstream of the login
//     is what the platform exists to collect, so eventually the door opens.
func (s *Server) acceptCredential(user, password string, attempt int) bool {
	if s.credentialAccepted(user, password) {
		return true
	}
	return attempt >= s.grantAfter()
}

// credentialAccepted reports whether this node's derived credential set
// contains the pair.
func (s *Server) credentialAccepted(user, password string) bool {
	accepted := s.acceptedCredentials()
	for _, c := range accepted {
		if c.user == user && c.pass == password {
			return true
		}
	}
	return false
}

type credential struct{ user, pass string }

// commonCredentials are drawn from what actually arrives at exposed sensors:
// vendor defaults, IoT firmware accounts, and the head of every published
// breach list. Each node adopts a slice of these.
var commonCredentials = []credential{
	{"root", "root"}, {"root", "123456"}, {"root", "admin"}, {"root", "password"},
	{"root", "toor"}, {"root", "1234"}, {"root", "12345"}, {"root", ""},
	{"root", "vizxv"}, {"root", "xc3511"}, {"root", "888888"}, {"root", "juantech"},
	{"root", "54321"}, {"root", "anko"}, {"root", "zlxx."}, {"root", "system"},
	{"root", "ikwb"}, {"root", "dreambox"}, {"root", "user"}, {"root", "realtek"},
	{"admin", "admin"}, {"admin", "1234"}, {"admin", "password"}, {"admin", ""},
	{"admin", "admin1234"}, {"admin", "12345"}, {"admin", "123456"},
	{"admin", "smcadmin"}, {"admin", "meinsm"}, {"admin", "7ujMko0admin"},
	{"user", "user"}, {"user", "password"}, {"test", "test"}, {"test", "1234"},
	{"guest", "guest"}, {"guest", "12345"}, {"oracle", "oracle"},
	{"ubuntu", "ubuntu"}, {"pi", "raspberry"}, {"debian", "debian"},
	{"support", "support"}, {"service", "service"}, {"supervisor", "supervisor"},
	{"ftp", "ftp"}, {"mysql", "mysql"}, {"postgres", "postgres"},
	{"deploy", "deploy"}, {"git", "git"}, {"jenkins", "jenkins"},
	{"default", "default"}, {"telnet", "telnet"}, {"ubnt", "ubnt"},
}

// acceptedCredentials returns this node's derived credential set. Computed on
// each call rather than cached: the derivation is cheap, the set is small, and
// avoiding shared mutable state keeps the auth path free of locking.
func (s *Server) acceptedCredentials() []credential {
	sum := sha256.Sum256([]byte("honeynet/credentials/v1:" + s.p.Seed))
	r := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(sum[:8])))) //nolint:gosec // deterministic per-node selection

	idx := r.Perm(len(commonCredentials))
	n := 3 + r.Intn(5)
	out := make([]credential, 0, n+1)
	for i := 0; i < n && i < len(idx); i++ {
		out = append(out, commonCredentials[idx[i]])
	}

	// Ensure at least one root credential works. A box where root never
	// authenticates sends most loaders away before they reveal anything.
	hasRoot := false
	for _, c := range out {
		if c.user == "root" {
			hasRoot = true
			break
		}
	}
	if !hasRoot {
		out = append(out, credential{"root", rootPasswords[r.Intn(len(rootPasswords))]})
	}
	return out
}

var rootPasswords = []string{"root", "123456", "admin", "password", "toor", "1234"}

// grantAfter is the failure count after which the node authenticates anything.
// Derived per node so the threshold is not a constant a scanner can learn.
func (s *Server) grantAfter() int {
	sum := sha256.Sum256([]byte("honeynet/grant-after/v1:" + s.p.Seed))
	return 2 + int(sum[0])%4 // 2..5
}

// NormalizeUsername trims the decorations that some clients attach, so that
// "root", "root " and "ROOT" cluster as one identity downstream while the raw
// form is still recorded verbatim in the event.
func NormalizeUsername(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}
