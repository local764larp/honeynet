package sshd

import (
	"regexp"
	"strconv"

	gossh "golang.org/x/crypto/ssh"
)

// The handshake is the first thing an attacker sees and the cheapest thing for
// them to check. Before this file existed the sensor announced itself as
// OpenSSH in the version banner and then negotiated with x/crypto/ssh's own
// defaults, which is a contradiction any scanner can read in one connection:
//
//	nmap --script ssh2-enum-algos -p22 host
//	ssh -vv host 2>&1 | grep 'kex algorithms'
//
// Go's defaults lead with mlkem768x25519-sha256, a post-quantum exchange that
// no OpenSSH 8.x has ever offered, and order the rest unlike any release. The
// server-side HASSH that falls out of it is a published constant that maps
// straight to "Go SSH library", which in practice means "honeypot".
//
// What follows pins the advertised algorithms to the release named in the
// banner, so the two halves of the claim agree.
//
// # Limits of this approach, stated plainly
//
// x/crypto/ssh can only advertise what it can negotiate, and it implements
// neither the umac-64/umac-128 MAC family nor diffie-hellman-group18-sha512.
// Every real OpenSSH offers the umac family and prefers it. A byte-exact match
// to a reference server is therefore not reachable on this library, and an
// analyst who diffs our KEXINIT against a real OpenSSH of the same version will
// still see a shorter MAC list.
//
// This file closes everything that is closeable: the post-quantum entry is
// gone, ordering follows OpenSSH's, and the cipher list matches exactly. What
// remains is the MAC gap. Closing that needs umac in the transport, which means
// carrying a patched x/crypto -- a real maintenance commitment and a decision
// for the operator, not one to make silently here.
//
// # Verifying the tables
//
// The lists below were transcribed from OpenSSH's myproposal.h per release.
// They are the one thing in this package that cannot be checked from inside
// the codebase, so treat them as needing a verification pass against real
// servers before a fleet goes out:
//
//	ssh -Q kex; ssh -Q cipher; ssh -Q mac        # on a host of that release
//	nmap --script ssh2-enum-algos -p22 <sensor>  # against the sensor
//
// TestAdvertisedAlgorithmsMatchProfile asserts that the sensor actually emits
// what the table claims, so a drift between code and table fails the build. It
// cannot tell you the table itself is right.

// profile is the handshake surface of one OpenSSH release, reduced to what this
// library can honestly negotiate.
type profile struct {
	// Name records which release the table was transcribed from, for the
	// failure message when the assertion test trips.
	Name string

	KexAlgos []string
	Ciphers  []string
	MACs     []string

	// HostKeyAlgos is what a stock sshd offers given the keys ssh-keygen -A
	// leaves in /etc/ssh.
	HostKeyAlgos []string

	// MaxAuthTries mirrors sshd_config's default. A server that lets an
	// attacker try indefinitely is not a server -- real sshd drops the
	// connection with "Too many authentication failures".
	MaxAuthTries int
}

// openSSH82 is the impersonation target with the smallest residual gap.
//
// 8.2p1 predates the sntrup761 hybrid exchange that 8.5 made default, so unlike
// the 8.5+ and 9.x releases there is no post-quantum entry we would have to
// omit. Its cipher list is reproduced here exactly. Only group18-sha512 and the
// umac MACs are beyond the library, which makes this the most convincing
// version the sensor can claim, and the banner weighting reflects that.
var openSSH82 = profile{
	Name: "OpenSSH_8.2p1",
	KexAlgos: []string{
		gossh.KeyExchangeCurve25519,
		gossh.KeyExchangeECDHP256,
		gossh.KeyExchangeECDHP384,
		gossh.KeyExchangeECDHP521,
		gossh.KeyExchangeDHGEXSHA256,
		gossh.KeyExchangeDH16SHA512,
		// group18-sha512 sits here on a real 8.2 and is not implemented.
		gossh.KeyExchangeDH14SHA256,
	},
	Ciphers: []string{
		gossh.CipherChaCha20Poly1305,
		gossh.CipherAES128CTR,
		gossh.CipherAES192CTR,
		gossh.CipherAES256CTR,
		gossh.CipherAES128GCM,
		gossh.CipherAES256GCM,
	},
	// The 8.2 list minus the 128-bit umac variants.
	//
	// umac-64 and hmac-sha1-etm come from the fork under third_party and are
	// verified two ways: the RFC 4418 vectors, and a real OpenSSH client
	// completing a session against this sensor with each one forced.
	//
	// umac-128 and umac-128-etm are deliberately absent. The implementation
	// passes every published vector it can be checked against -- the RFC
	// covers UMAC-64 and UMAC-96, and both pass -- but a real OpenSSH client
	// rejects the 128-bit variants with "Corrupted MAC on input". The Go-to-Go
	// interop test did not catch it because both ends ran the same wrong code.
	//
	// Advertising them would be worse than the gap they close. OpenSSH lists
	// umac-128-etm second, so most clients prefer it, and a server that
	// negotiates a MAC it computes incorrectly does not look like an unusual
	// server -- it looks like a broken one, and drops the session before
	// anything worth collecting happens.
	//
	// The code stays in the fork behind its tests. Fixing it needs UMAC-128
	// vectors, which the RFC appendix has and which could not be extracted
	// here; a real OpenSSH server also works as an oracle.
	MACs: []string{
		gossh.UMAC64ETM,
		gossh.HMACSHA256ETM,
		gossh.HMACSHA512ETM,
		gossh.HMACSHA1ETM,
		gossh.UMAC64,
		gossh.HMACSHA256,
		gossh.HMACSHA512,
		gossh.HMACSHA1,
	},
	HostKeyAlgos: []string{
		gossh.KeyAlgoRSASHA512,
		gossh.KeyAlgoRSASHA256,
		gossh.KeyAlgoECDSA256,
		gossh.KeyAlgoED25519,
	},
	MaxAuthTries: 6,
}

// openSSH89 covers the 8.5-and-later line. Identical to 8.2 in everything this
// library can reach; the difference on a real server is the sntrup761 hybrid at
// the head of the KEX list, which we cannot offer.
//
// That omission is itself a discrepancy, which is why the banner weighting
// prefers 8.2. Kept so the fleet is not uniformly one version, which would be
// its own anomaly.
var openSSH89 = profile{
	Name:         "OpenSSH_8.9p1",
	KexAlgos:     openSSH82.KexAlgos,
	Ciphers:      openSSH82.Ciphers,
	MACs:         openSSH82.MACs,
	HostKeyAlgos: openSSH82.HostKeyAlgos,
	MaxAuthTries: 6,
}

var versionPattern = regexp.MustCompile(`OpenSSH[_-](\d+)\.(\d+)`)

// profileFor selects the algorithm table for a banner.
//
// Defaults to the 8.2 table for anything unrecognised. A wrong-but-coherent
// handshake is recoverable; falling through to the library's own defaults would
// reintroduce the post-quantum entry and undo the point of this file.
func profileFor(banner string) profile {
	m := versionPattern.FindStringSubmatch(banner)
	if m == nil {
		return openSSH82
	}

	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])

	switch {
	case major > 8 || (major == 8 && minor >= 5):
		return openSSH89
	default:
		return openSSH82
	}
}

// advertisedKex returns the key exchange list as it actually appears on the
// wire, which is not quite the configured list.
//
// x/crypto injects two entries that Config cannot suppress. Both turn out to be
// right for the releases impersonated here, which is why they are modelled
// rather than fought:
//
//   - curve25519-sha256@libssh.org is the historical alias, and every OpenSSH
//     advertises it immediately after curve25519-sha256. The library inserts it
//     in that same position.
//
//   - kex-strict-s-v00@openssh.com is the strict-KEX marker introduced to
//     mitigate Terrapin (CVE-2023-48795), and OpenSSH appends it last. Every
//     banner in the personality pool names a distribution security build --
//     Ubuntu-4ubuntu0.11, Debian-2+deb12u2 and so on -- which is precisely the
//     kind of build that carries the backported fix. A patched 8.2p1 that did
//     not advertise strict-KEX would be the more suspicious of the two.
//
// Modelled here so the assertion test compares against the real wire format and
// still fails on any drift we do control.
func (p profile) advertisedKex() []string {
	out := make([]string, 0, len(p.KexAlgos)+2)
	for _, k := range p.KexAlgos {
		out = append(out, k)
		if k == gossh.KeyExchangeCurve25519 {
			out = append(out, "curve25519-sha256@libssh.org")
		}
	}
	return append(out, "kex-strict-s-v00@openssh.com")
}

// serverConfig applies the profile to the transport configuration.
//
// This is the only place the handshake surface is set. gliderlabs would
// otherwise hand x/crypto its zero-value Config, which means library defaults.
func (p profile) serverConfig() *gossh.ServerConfig {
	cfg := &gossh.ServerConfig{
		MaxAuthTries: p.MaxAuthTries,
	}
	cfg.KeyExchanges = append([]string(nil), p.KexAlgos...)
	cfg.Ciphers = append([]string(nil), p.Ciphers...)
	cfg.MACs = append([]string(nil), p.MACs...)
	return cfg
}
