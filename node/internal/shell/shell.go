// Package shell implements the emulated command interpreter.
//
// Containment invariant: this package contains no execution path. It does not
// import os/exec, it does not spawn processes, and it never opens a network
// connection on behalf of a session. Every command is answered from the
// in-memory VFS and the node's derived personality. A CI lint enforces the
// import restriction -- see deploy/lint.
package shell

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/honeynet/node/internal/personality"
	"github.com/honeynet/node/internal/vfs"
)

// CommandEvent is one line of attacker input, with the timing metadata that
// drives bot/human classification downstream.
type CommandEvent struct {
	Raw         string
	Argv        []string
	ParseFailed bool
	Cwd         string
	SinceStart  time.Duration
	SincePrev   time.Duration

	// KeystrokeDeltasMS holds inter-arrival gaps between input reads. Humans
	// produce irregular gaps with pauses at word boundaries; scripts deliver
	// whole lines in a single read and yield an empty slice with BulkInput set.
	KeystrokeDeltasMS []uint32
	BulkInput         bool

	Index uint32
}

// ArtifactEvent records a URL the attacker asked the node to fetch. The node
// does not fetch it.
type ArtifactEvent struct {
	URL           string
	ViaTool       string
	SourceCommand string
}

// UploadEvent records bytes the attacker actually pushed into the VFS.
type UploadEvent struct {
	Path        string
	Content     []byte
	ClaimedName string
	Transport   string
}

// Hooks receive observations. All are optional.
type Hooks struct {
	OnCommand  func(CommandEvent)
	OnArtifact func(ArtifactEvent)
	OnUpload   func(UploadEvent)
}

// Limits bound what one session can consume. Exceeding any of them ends the
// session with SESSION_END_REASON_LIMIT_EXCEEDED rather than letting a single
// peer occupy the node indefinitely.
type Limits struct {
	MaxCommands   int
	MaxInputBytes int64
	IdleTimeout   time.Duration
	MaxDuration   time.Duration
}

// DefaultLimits are tuned for real internet exposure: generous enough that a
// full Mirai infection chain completes and is recorded end to end, tight enough
// that a single peer cannot pin the node.
func DefaultLimits() Limits {
	return Limits{
		MaxCommands:   500,
		MaxInputBytes: 4 << 20,
		IdleTimeout:   3 * time.Minute,
		MaxDuration:   30 * time.Minute,
	}
}

// Shell is one interactive or exec session against the emulated system.
type Shell struct {
	p     *personality.Personality
	fs    *vfs.FS
	hooks Hooks
	lim   Limits

	rw  io.ReadWriter
	pty bool

	user string
	uid  int
	gid  int
	cwd  string
	env  map[string]string

	history  []string
	cmdIndex uint32
	exitCode int

	start    time.Time
	lastCmd  time.Time
	inBytes  int64
	exitFlag bool

	// LoginTime is reported by `who`, `w` and `last`, and must agree with the
	// session's actual start rather than the personality boot time.
	loginTime time.Time
}

// ErrSessionEnded is returned by Run when the attacker disconnected or exited
// normally. It is not a failure.
var ErrSessionEnded = errors.New("session ended")

// ErrLimitExceeded is returned when a session tripped one of the Limits.
var ErrLimitExceeded = errors.New("session limit exceeded")

// New creates a shell bound to a session's I/O.
func New(p *personality.Personality, fs *vfs.FS, rw io.ReadWriter, user string, pty bool, hooks Hooks, lim Limits) *Shell {
	uid, gid, home := 0, 0, "/root"
	for _, u := range p.Users {
		if u.Name == user {
			uid, gid, home = u.UID, u.GID, u.Home
			break
		}
	}
	if user != "root" && uid == 0 {
		// Unknown username that authenticated anyway. Real sshd would have
		// rejected it, but honeypots accept broadly to see what happens next,
		// so synthesise a plausible unprivileged identity.
		uid, gid, home = 1000, 1000, "/home/"+user
	}

	now := time.Now()
	sh := &Shell{
		p: p, fs: fs, rw: rw, pty: pty, hooks: hooks, lim: lim,
		user: user, uid: uid, gid: gid, cwd: home,
		start: now, lastCmd: now, loginTime: now,
		env: map[string]string{
			"SHELL":    "/bin/bash",
			"PWD":      home,
			"LOGNAME":  user,
			"HOME":     home,
			"USER":     user,
			"PATH":     "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
			"LANG":     "en_US.UTF-8",
			"TERM":     "xterm-256color",
			"HOSTNAME": p.Hostname,
			"SHLVL":    "1",
			"_":        "/usr/bin/env",
		},
	}
	if !fs.Exists(home) {
		sh.cwd = "/"
		sh.env["PWD"] = "/"
	}
	return sh
}

// ExitCode reports the exit status of the last command run.
func (s *Shell) ExitCode() int { return s.exitCode }

// CommandCount reports how many command lines were processed.
func (s *Shell) CommandCount() uint32 { return s.cmdIndex }

// RunExec handles a non-interactive invocation -- `ssh host "uname -a"`. Bots
// use this constantly because it avoids PTY allocation, and the whole payload
// arrives in one string.
func (s *Shell) RunExec(line string) error {
	s.observe(line, nil, true)
	s.execLine(line)
	return nil
}

// RunInteractive drives a PTY session: banner, prompt, read-eval loop.
func (s *Shell) RunInteractive() error {
	s.writeMOTD()

	for {
		if s.exitFlag {
			return ErrSessionEnded
		}
		if int(s.cmdIndex) >= s.lim.MaxCommands {
			s.printf("\r\n-bash: fork: retry: Resource temporarily unavailable\r\n")
			return ErrLimitExceeded
		}
		if time.Since(s.start) > s.lim.MaxDuration {
			return ErrLimitExceeded
		}

		s.writePrompt()

		line, deltas, bulk, err := s.readLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return ErrSessionEnded
			}
			return err
		}
		if strings.TrimSpace(line) == "" {
			continue
		}

		s.history = append(s.history, line)
		s.observe(line, deltas, bulk)
		s.execLine(line)
	}
}

// readLine reads one line in PTY mode, echoing as it goes and recording the
// inter-arrival gap of every read. A read that delivers more than one printable
// byte is treated as pasted rather than typed.
func (s *Shell) readLine() (string, []uint32, bool, error) {
	var buf []rune
	var deltas []uint32
	bulk := false
	last := time.Now()
	histPos := len(s.history)

	chunk := make([]byte, 256)
	for {
		n, err := s.rw.Read(chunk)
		if err != nil {
			return string(buf), deltas, bulk, err
		}
		if n == 0 {
			continue
		}

		now := time.Now()
		gap := now.Sub(last)
		last = now
		if ms := gap.Milliseconds(); ms >= 0 && ms < 1<<31 {
			deltas = append(deltas, uint32(ms))
		}

		s.inBytes += int64(n)
		if s.inBytes > s.lim.MaxInputBytes {
			return string(buf), deltas, bulk, ErrLimitExceeded
		}

		// More than two printable bytes in one read means the client did not
		// type them individually.
		printable := 0
		for _, b := range chunk[:n] {
			if b >= 0x20 && b != 0x7f {
				printable++
			}
		}
		if printable > 2 {
			bulk = true
		}

		for i := 0; i < n; i++ {
			b := chunk[i]
			switch b {
			case '\r', '\n':
				s.printf("\r\n")
				return string(buf), deltas, bulk, nil

			case 0x03: // Ctrl-C
				s.printf("^C\r\n")
				buf = buf[:0]
				s.writePrompt()

			case 0x04: // Ctrl-D
				if len(buf) == 0 {
					s.printf("logout\r\n")
					s.exitFlag = true
					return "", deltas, bulk, io.EOF
				}

			case 0x7f, 0x08: // backspace
				if len(buf) > 0 {
					buf = buf[:len(buf)-1]
					s.printf("\b \b")
				}

			case 0x15: // Ctrl-U
				for range buf {
					s.printf("\b \b")
				}
				buf = buf[:0]

			case 0x1b: // escape sequence: arrows for history
				if i+2 < n && chunk[i+1] == '[' {
					switch chunk[i+2] {
					case 'A': // up
						if histPos > 0 {
							histPos--
							buf = s.replaceLine(buf, s.history[histPos])
						}
					case 'B': // down
						if histPos < len(s.history)-1 {
							histPos++
							buf = s.replaceLine(buf, s.history[histPos])
						} else {
							histPos = len(s.history)
							buf = s.replaceLine(buf, "")
						}
					}
					i += 2
				}

			case '\t':
				// Real bash would complete. Emitting nothing is the safest
				// behaviour: a wrong completion is a louder tell than none.

			default:
				if b >= 0x20 {
					buf = append(buf, rune(b))
					s.printf("%c", b)
				}
			}
		}
	}
}

func (s *Shell) replaceLine(buf []rune, next string) []rune {
	for range buf {
		s.printf("\b \b")
	}
	s.printf("%s", next)
	return []rune(next)
}

// observe reports a command line to the hooks, including any URLs it referenced.
func (s *Shell) observe(line string, deltas []uint32, bulk bool) {
	now := time.Now()
	pipelines := Parse(line)

	var argv []string
	parseFailed := len(pipelines) == 0
	if !parseFailed && len(pipelines[0].Stages) > 0 {
		argv = pipelines[0].Stages[0].Argv
	}

	if s.hooks.OnCommand != nil {
		s.hooks.OnCommand(CommandEvent{
			Raw:               line,
			Argv:              argv,
			ParseFailed:       parseFailed,
			Cwd:               s.cwd,
			SinceStart:        now.Sub(s.start),
			SincePrev:         now.Sub(s.lastCmd),
			KeystrokeDeltasMS: deltas,
			BulkInput:         bulk,
			Index:             s.cmdIndex,
		})
	}

	if s.hooks.OnArtifact != nil {
		for _, pl := range pipelines {
			for _, st := range pl.Stages {
				tool := ""
				if len(st.Argv) > 0 {
					tool = st.Argv[0]
				}
				for _, u := range ExtractURLs(st.Argv) {
					s.hooks.OnArtifact(ArtifactEvent{URL: u, ViaTool: tool, SourceCommand: line})
				}
			}
		}
	}

	s.lastCmd = now
	s.cmdIndex++
}

// execLine evaluates a full command line, honouring ; && || and pipes.
func (s *Shell) execLine(line string) {
	for _, pl := range Parse(line) {
		s.runPipeline(pl)

		switch pl.Next {
		case "&&":
			if s.exitCode != 0 {
				return
			}
		case "||":
			if s.exitCode == 0 {
				return
			}
		}
		if s.exitFlag {
			return
		}
	}
}

// runPipeline executes the stages of one pipeline, threading stdout of each
// into stdin of the next.
func (s *Shell) runPipeline(pl Pipeline) {
	var carry string
	for i, st := range pl.Stages {
		if len(st.Argv) == 0 {
			continue
		}
		last := i == len(pl.Stages)-1

		out, code := s.runStage(st, carry)
		s.exitCode = code

		switch {
		case st.RedirectOut != "":
			target := vfs.Clean(s.cwd, st.RedirectOut)
			if err := s.fs.WriteFile(target, []byte(out), 0o644, s.uid, s.gid); err != nil {
				s.errf("bash: %s: %v", st.RedirectOut, err)
				s.exitCode = 1
			} else if s.hooks.OnUpload != nil && len(out) > 0 {
				s.hooks.OnUpload(UploadEvent{
					Path: target, Content: []byte(out),
					ClaimedName: st.RedirectOut, Transport: "shell-redirect",
				})
			}
			carry = ""

		case st.RedirectAppend != "":
			target := vfs.Clean(s.cwd, st.RedirectAppend)
			if err := s.fs.Append(target, []byte(out), s.uid, s.gid); err != nil {
				s.errf("bash: %s: %v", st.RedirectAppend, err)
				s.exitCode = 1
			}
			carry = ""

		case last:
			s.write(out)
			carry = ""

		default:
			carry = out
		}
	}
}

// ---- output helpers ----
//
// In PTY mode the client expects CRLF. Commands generate plain LF, so every
// write translates on the way out; getting this wrong produces staircase output
// that immediately marks the host as emulated.

func (s *Shell) write(str string) {
	if str == "" {
		return
	}
	if s.pty {
		str = strings.ReplaceAll(str, "\r\n", "\n")
		str = strings.ReplaceAll(str, "\n", "\r\n")
	}
	_, _ = io.WriteString(s.rw, str)
}

func (s *Shell) printf(format string, a ...any) {
	_, _ = io.WriteString(s.rw, fmt.Sprintf(format, a...))
}

func (s *Shell) errf(format string, a ...any) {
	s.write(fmt.Sprintf(format, a...) + "\n")
}

func (s *Shell) writePrompt() {
	host := strings.SplitN(s.p.Hostname, ".", 2)[0]
	disp := s.cwd
	if home := s.env["HOME"]; home != "/" && strings.HasPrefix(disp, home) {
		disp = "~" + strings.TrimPrefix(disp, home)
	}
	sigil := "$"
	if s.uid == 0 {
		sigil = "#"
	}
	s.printf("%s@%s:%s%s ", s.user, host, disp, sigil)
}

func (s *Shell) writeMOTD() {
	if motd := s.p.MOTD(); motd != "" {
		s.printf("%s", motd)
	}
	s.printf("Last login: %s from %s\r\n",
		s.loginTime.Add(-time.Duration(3+s.uid%20)*time.Hour).Format("Mon Jan  2 15:04:05 2006"),
		"10.0.0."+fmt.Sprint(20+s.uid%200))
}
