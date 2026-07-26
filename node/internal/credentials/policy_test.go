package credentials

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

var roster = []string{"root", "admin", "ubuntu", "deploy", "jennifer"}

func newTestPolicy(t *testing.T) *Policy {
	t.Helper()
	return NewPolicy("node-secret-under-test", roster)
}

// The property the whole design rests on: exactly one password authenticates
// per account. If a second string ever works, a detection script finds it by
// reconnecting once.
func TestOnlyOnePasswordAuthenticates(t *testing.T) {
	p := newTestPolicy(t)

	for _, acct := range roster {
		want, ok := p.PasswordFor(acct)
		if !ok {
			t.Fatalf("account %q missing from policy", acct)
		}
		if !p.Accept(acct, want) {
			t.Errorf("account %q rejected its own password %q", acct, want)
		}

		// Every other account's password must fail against this one.
		for _, other := range roster {
			if other == acct {
				continue
			}
			pw, _ := p.PasswordFor(other)
			if pw == want {
				continue // legitimate collision, not a second password
			}
			if p.Accept(acct, pw) {
				t.Errorf("account %q accepted %q, a second working password", acct, pw)
			}
		}
	}
}

// The detection probe this package exists to defeat: spray random
// high-entropy strings and see whether persistence eventually opens the door.
func TestRandomCredentialsNeverAuthenticate(t *testing.T) {
	p := newTestPolicy(t)

	for i := 0; i < 2000; i++ {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("rand: %v", err)
		}
		guess := hex.EncodeToString(buf)

		for _, acct := range roster {
			if p.Accept(acct, guess) {
				t.Fatalf("random credential %s:%s authenticated on attempt %d", acct, guess, i)
			}
		}
	}
}

// Persistence must not be rewarded. The old behaviour granted access purely on
// attempt count; nothing in the current path can, but assert it directly so a
// reintroduced counter fails here.
func TestRepeatedFailuresNeverGrantAccess(t *testing.T) {
	p := newTestPolicy(t)

	for attempt := 1; attempt <= 500; attempt++ {
		if p.Accept("root", "definitely-not-the-password") {
			t.Fatalf("wrong password authenticated after %d attempts", attempt)
		}
	}
}

func TestUnknownAccountsRejected(t *testing.T) {
	p := newTestPolicy(t)

	for _, name := range []string{"nosuchuser", "", "  ", "root\x00", "../root"} {
		if p.Accept(name, "root") {
			t.Errorf("unknown account %q authenticated", name)
		}
	}
}

// A node must present the same credentials across restarts. The host key is
// persisted for the same reason: scanners revisit, and a box whose password
// changed between two visits is not a box.
func TestDerivationIsDeterministic(t *testing.T) {
	a := NewPolicy("stable-secret", roster)
	b := NewPolicy("stable-secret", roster)

	for _, acct := range roster {
		pa, _ := a.PasswordFor(acct)
		pb, _ := b.PasswordFor(acct)
		if pa != pb {
			t.Errorf("account %q derived %q then %q", acct, pa, pb)
		}
	}
}

// Two sensors must not share credentials, or compromising one hands over the
// fleet.
func TestDistinctSecretsProduceDistinctCredentials(t *testing.T) {
	a := NewPolicy("secret-one", roster)
	b := NewPolicy("secret-two", roster)

	same := 0
	for _, acct := range roster {
		pa, _ := a.PasswordFor(acct)
		pb, _ := b.PasswordFor(acct)
		if pa == pb {
			same++
		}
	}
	if same == len(roster) {
		t.Error("two secrets derived an identical credential set")
	}
}

// Accounts on one node must not share a password. Deriving from the node
// secret alone would produce exactly that, and one guess would expose the box.
func TestAccountsDoNotAllShareAPassword(t *testing.T) {
	p := NewPolicy("shared-check", roster)

	seen := map[string]int{}
	for _, acct := range roster {
		pw, _ := p.PasswordFor(acct)
		seen[pw]++
	}
	if len(seen) == 1 {
		t.Errorf("all %d accounts derived the same password", len(roster))
	}
}

// The premise of the deception: the shared operational accounts are guessable
// from a standard list, so a botnet spraying one actually gets in.
func TestWeakAccountsDrawFromTheSprayedHead(t *testing.T) {
	head := map[string]bool{}
	for _, pw := range headPasswords {
		head[pw] = true
	}

	// Sample across many secrets: the assertion is about the population, not
	// about one node's draw.
	for i := 0; i < 200; i++ {
		p := NewPolicy("secret-"+hex.EncodeToString([]byte{byte(i)}), []string{"root", "jennifer"})

		rootPw, _ := p.PasswordFor("root")
		if !head[rootPw] {
			t.Fatalf("root drew %q, which is not in the sprayed head", rootPw)
		}

		humanPw, _ := p.PasswordFor("jennifer")
		if head[humanPw] {
			t.Fatalf("named account drew %q from the sprayed head", humanPw)
		}
	}
}

func TestAccountsReportsRoster(t *testing.T) {
	p := newTestPolicy(t)
	got := p.Accounts()
	if len(got) != len(roster) {
		t.Fatalf("got %d accounts, want %d: %v", len(got), len(roster), got)
	}
}
