// Package vfs implements the in-memory filesystem the emulated shell operates
// on. Nothing here ever touches the real host filesystem.
//
// Attacker writes are accepted and retained for the lifetime of the session --
// a bot that drops a payload and then cats it back must see its own bytes, or
// it detects the emulation -- but they live only in this tree and are discarded
// when the session ends.
package vfs

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/honeynet/node/internal/personality"
)

var (
	ErrNotFound     = errors.New("no such file or directory")
	ErrNotDir       = errors.New("not a directory")
	ErrIsDir        = errors.New("is a directory")
	ErrPermission   = errors.New("permission denied")
	ErrExists       = errors.New("file exists")
	ErrNotEmpty     = errors.New("directory not empty")
	ErrLinkLoop     = errors.New("too many levels of symbolic links")
	ErrQuotaReached = errors.New("no space left on device")
)

// maxWriteBytes bounds what one session can push into the tree. Without it a
// `dd if=/dev/zero of=/tmp/x` loop is a trivial memory exhaustion attack
// against the node.
const maxWriteBytes = 32 << 20 // 32 MiB

type Kind uint8

const (
	KindFile Kind = iota
	KindDir
	KindSymlink
)

// Node is one filesystem entry.
type Node struct {
	Name    string
	Kind    Kind
	Mode    uint32
	UID     int
	GID     int
	ModTime time.Time
	Target  string // symlink destination

	content []byte

	// dynamic backs procfs-style files whose contents are computed on read
	// (uptime, meminfo). When set it takes precedence over content.
	dynamic func() string

	children map[string]*Node

	// AttackerWritten marks entries created or modified during the session, so
	// the session reporter can enumerate dropped files without diffing the
	// whole tree.
	AttackerWritten bool
}

// FS is a per-session filesystem. Each session gets its own so that one
// attacker's droppings are never visible to another.
type FS struct {
	root    *Node
	p       *personality.Personality
	written int64
}

func dir(name string, mode uint32, uid, gid int, mt time.Time) *Node {
	return &Node{Name: name, Kind: KindDir, Mode: mode, UID: uid, GID: gid,
		ModTime: mt, children: map[string]*Node{}}
}

func file(name string, mode uint32, uid, gid int, mt time.Time, content string) *Node {
	return &Node{Name: name, Kind: KindFile, Mode: mode, UID: uid, GID: gid,
		ModTime: mt, content: []byte(content)}
}

func dynfile(name string, mode uint32, fn func() string) *Node {
	return &Node{Name: name, Kind: KindFile, Mode: mode, ModTime: time.Now(), dynamic: fn}
}

func symlink(name, target string, mt time.Time) *Node {
	return &Node{Name: name, Kind: KindSymlink, Mode: 0o777, ModTime: mt, Target: target}
}

// New builds a filesystem consistent with the given personality. File mtimes
// are anchored to the derived boot time so that `ls -la /` does not show a
// machine whose entire root was created five minutes ago.
func New(p *personality.Personality) *FS {
	boot := p.BootTime
	install := boot.Add(-time.Duration(30*24) * time.Hour)

	fs := &FS{p: p, root: dir("/", 0o755, 0, 0, install)}

	for _, d := range []string{
		"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media",
		"/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys",
		"/tmp", "/usr", "/var",
		"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local", "/usr/local/bin",
		"/usr/local/sbin", "/usr/share", "/usr/src",
		"/var/log", "/var/tmp", "/var/www", "/var/www/html", "/var/spool",
		"/var/spool/cron", "/var/spool/cron/crontabs", "/var/backups",
		"/var/cache", "/var/lib", "/var/run",
		"/etc/ssh", "/etc/cron.d", "/etc/cron.daily", "/etc/init.d",
		"/etc/systemd", "/etc/systemd/system", "/etc/apt", "/etc/network",
		"/dev/shm", "/dev/pts", "/run/lock",
	} {
		fs.mkdirAll(d, 0o755, 0, 0, install)
	}

	fs.chmodNode("/tmp", 0o1777)
	fs.chmodNode("/var/tmp", 0o1777)
	fs.chmodNode("/dev/shm", 0o1777)
	fs.chmodNode("/root", 0o700)

	// Home directories, each with the shell dotfiles a real account has.
	for _, u := range p.Users {
		if u.UID == 0 {
			continue
		}
		fs.mkdirAll(u.Home, 0o755, u.UID, u.GID, install)
		fs.put(path.Join(u.Home, ".bashrc"), file(".bashrc", 0o644, u.UID, u.GID, install, bashrc))
		fs.put(path.Join(u.Home, ".profile"), file(".profile", 0o644, u.UID, u.GID, install, profile))
		fs.put(path.Join(u.Home, ".bash_logout"), file(".bash_logout", 0o644, u.UID, u.GID, install, bashLogout))
	}
	fs.put("/root/.bashrc", file(".bashrc", 0o644, 0, 0, install, rootBashrc))
	fs.put("/root/.profile", file(".profile", 0o644, 0, 0, install, profile))

	// Static /etc content, derived so it agrees with the personality.
	etc := map[string]string{
		"/etc/hostname":      p.Hostname + "\n",
		"/etc/hosts":         fmt.Sprintf("127.0.0.1\tlocalhost\n127.0.1.1\t%s\n\n::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n", p.Hostname),
		"/etc/os-release":    p.OSRelease(),
		"/etc/passwd":        p.Passwd(),
		"/etc/machine-id":    p.MachineID() + "\n",
		"/etc/resolv.conf":   "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n",
		"/etc/timezone":      "Etc/UTC\n",
		"/etc/debian_version": p.Distro.VersionID + "\n",
		"/etc/issue":         p.Distro.PrettyName + " \\n \\l\n\n",
		"/etc/fstab":         "UUID=" + p.MachineID()[:8] + "-" + p.MachineID()[8:12] + " / ext4 defaults 0 1\n",
		"/etc/crontab":       etcCrontab,
		"/etc/motd":          "",
	}
	for pth, content := range etc {
		fs.put(pth, file(path.Base(pth), 0o644, 0, 0, install, content))
	}

	// /etc/shadow exists but is unreadable, which is itself realistic: a bot
	// that gets "permission denied" learns it is not root, and that decision
	// point is useful behavioural signal.
	fs.put("/etc/shadow", file("shadow", 0o640, 0, 42, install, shadowFor(p)))

	fs.put("/etc/ssh/sshd_config", file("sshd_config", 0o644, 0, 0, install, sshdConfig))

	// Dynamic /proc entries, recomputed per read so uptime advances during a
	// long session rather than freezing.
	fs.put("/proc/cpuinfo", dynfile("cpuinfo", 0o444, p.ProcCPUInfo))
	fs.put("/proc/meminfo", dynfile("meminfo", 0o444, p.ProcMemInfo))
	fs.put("/proc/version", dynfile("version", 0o444, p.ProcVersion))
	fs.put("/proc/uptime", dynfile("uptime", 0o444, p.ProcUptime))
	fs.put("/proc/filesystems", file("filesystems", 0o444, 0, 0, boot, procFilesystems))
	fs.put("/proc/mounts", file("mounts", 0o444, 0, 0, boot, procMounts))
	fs.put("/proc/self/status", file("status", 0o444, 0, 0, boot, "Name:\tbash\nState:\tS (sleeping)\nPid:\t2841\nPPid:\t2840\n"))
	fs.put("/proc/loadavg", dynfile("loadavg", 0o444, func() string {
		return fmt.Sprintf("0.0%d 0.0%d 0.0%d 1/%d %d\n", 2, 4, 1, 118+len(p.Packages), 20000+len(p.Hostname)*37)
	}))

	// Binaries. Contents are inert placeholder bytes -- the emulator dispatches
	// on name, and nothing here is ever executed -- but they must stat as real
	// files with plausible sizes, because `ls -la /bin` is a common probe.
	for _, b := range coreutils {
		fs.put("/bin/"+b, file(b, 0o755, 0, 0, install, elfStub))
	}
	for _, b := range usrBins {
		fs.put("/usr/bin/"+b, file(b, 0o755, 0, 0, install, elfStub))
	}
	for _, b := range sbins {
		fs.put("/sbin/"+b, file(b, 0o755, 0, 0, install, elfStub))
	}
	fs.put("/bin/sh", symlink("sh", "dash", install))

	fs.put("/var/log/wtmp", file("wtmp", 0o664, 0, 43, boot, ""))
	fs.put("/var/log/lastlog", file("lastlog", 0o644, 0, 0, boot, ""))
	fs.put("/var/log/auth.log", file("auth.log", 0o640, 0, 4, time.Now().Add(-time.Hour), ""))
	fs.put("/var/log/syslog", file("syslog", 0o640, 0, 4, time.Now().Add(-time.Minute*3), ""))

	return fs
}

func shadowFor(p *personality.Personality) string {
	var b strings.Builder
	for _, u := range p.Users {
		fmt.Fprintf(&b, "%s:!:19700:0:99999:7:::\n", u.Name)
	}
	return b.String()
}

// ---- path resolution ----

// Clean normalises a path against a working directory, resolving . and ..
// without ever escaping the root.
func Clean(cwd, p string) string {
	if p == "" {
		return cwd
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(cwd, p)
	}
	c := path.Clean(p)
	if !strings.HasPrefix(c, "/") {
		c = "/" + c
	}
	return c
}

func split(p string) []string {
	p = path.Clean(p)
	if p == "/" || p == "." {
		return nil
	}
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

// lookup walks to a node. When follow is true a terminal symlink is resolved.
func (f *FS) lookup(p string, follow bool) (*Node, error) {
	return f.lookupDepth(p, follow, 0)
}

func (f *FS) lookupDepth(p string, follow bool, depth int) (*Node, error) {
	if depth > 16 {
		return nil, ErrLinkLoop
	}
	cur := f.root
	parts := split(p)
	for i, part := range parts {
		if cur.Kind == KindSymlink {
			resolved := Clean(path.Dir(p), cur.Target)
			var err error
			cur, err = f.lookupDepth(resolved, true, depth+1)
			if err != nil {
				return nil, err
			}
		}
		if cur.Kind != KindDir {
			return nil, ErrNotDir
		}
		next, ok := cur.children[part]
		if !ok {
			return nil, ErrNotFound
		}
		cur = next
		if i == len(parts)-1 && cur.Kind == KindSymlink && follow {
			resolved := Clean(path.Dir(Clean("/", p)), cur.Target)
			return f.lookupDepth(resolved, true, depth+1)
		}
	}
	return cur, nil
}

// Stat returns the node at p, following a terminal symlink.
func (f *FS) Stat(p string) (*Node, error) { return f.lookup(p, true) }

// Lstat returns the node at p without following a terminal symlink.
func (f *FS) Lstat(p string) (*Node, error) { return f.lookup(p, false) }

// Exists reports whether p resolves.
func (f *FS) Exists(p string) bool { _, err := f.lookup(p, true); return err == nil }

// IsDir reports whether p resolves to a directory.
func (f *FS) IsDir(p string) bool {
	n, err := f.lookup(p, true)
	return err == nil && n.Kind == KindDir
}

// ReadFile returns file contents, evaluating dynamic files on each call.
func (f *FS) ReadFile(p string) ([]byte, error) {
	n, err := f.lookup(p, true)
	if err != nil {
		return nil, err
	}
	if n.Kind == KindDir {
		return nil, ErrIsDir
	}
	if n.dynamic != nil {
		return []byte(n.dynamic()), nil
	}
	return n.content, nil
}

// ReadDir returns the entries of a directory, sorted by name.
func (f *FS) ReadDir(p string) ([]*Node, error) {
	n, err := f.lookup(p, true)
	if err != nil {
		return nil, err
	}
	if n.Kind != KindDir {
		return nil, ErrNotDir
	}
	out := make([]*Node, 0, len(n.children))
	for _, c := range n.children {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// WriteFile stores attacker-supplied content. Bounded by maxWriteBytes across
// the session; the shell surfaces the overflow as ENOSPC, which is a response a
// real box could plausibly give.
func (f *FS) WriteFile(p string, content []byte, mode uint32, uid, gid int) error {
	if f.written+int64(len(content)) > maxWriteBytes {
		return ErrQuotaReached
	}
	parent := path.Dir(p)
	pn, err := f.lookup(parent, true)
	if err != nil {
		return err
	}
	if pn.Kind != KindDir {
		return ErrNotDir
	}
	name := path.Base(p)
	if existing, ok := pn.children[name]; ok && existing.Kind == KindDir {
		return ErrIsDir
	}
	f.written += int64(len(content))
	pn.children[name] = &Node{
		Name: name, Kind: KindFile, Mode: mode, UID: uid, GID: gid,
		ModTime: time.Now(), content: content, AttackerWritten: true,
	}
	return nil
}

// Append adds to an existing file, creating it when absent.
func (f *FS) Append(p string, content []byte, uid, gid int) error {
	n, err := f.lookup(p, true)
	if err != nil {
		return f.WriteFile(p, content, 0o644, uid, gid)
	}
	if n.Kind == KindDir {
		return ErrIsDir
	}
	if f.written+int64(len(content)) > maxWriteBytes {
		return ErrQuotaReached
	}
	f.written += int64(len(content))
	n.content = append(n.content, content...)
	n.ModTime = time.Now()
	n.AttackerWritten = true
	return nil
}

// Mkdir creates a single directory.
func (f *FS) Mkdir(p string, mode uint32, uid, gid int) error {
	parent, err := f.lookup(path.Dir(p), true)
	if err != nil {
		return err
	}
	if parent.Kind != KindDir {
		return ErrNotDir
	}
	name := path.Base(p)
	if _, ok := parent.children[name]; ok {
		return ErrExists
	}
	d := dir(name, mode, uid, gid, time.Now())
	d.AttackerWritten = true
	parent.children[name] = d
	return nil
}

// MkdirAll creates a directory and any missing parents.
func (f *FS) MkdirAll(p string, mode uint32, uid, gid int) error {
	f.mkdirAll(p, mode, uid, gid, time.Now())
	return nil
}

// Remove unlinks a file, or an empty directory unless recursive is set.
func (f *FS) Remove(p string, recursive bool) error {
	if p == "/" {
		return ErrPermission
	}
	parent, err := f.lookup(path.Dir(p), true)
	if err != nil {
		return err
	}
	name := path.Base(p)
	n, ok := parent.children[name]
	if !ok {
		return ErrNotFound
	}
	if n.Kind == KindDir && len(n.children) > 0 && !recursive {
		return ErrNotEmpty
	}
	delete(parent.children, name)
	return nil
}

// Rename moves an entry.
func (f *FS) Rename(from, to string) error {
	fromParent, err := f.lookup(path.Dir(from), true)
	if err != nil {
		return err
	}
	n, ok := fromParent.children[path.Base(from)]
	if !ok {
		return ErrNotFound
	}
	toParent, err := f.lookup(path.Dir(to), true)
	if err != nil {
		return err
	}
	delete(fromParent.children, path.Base(from))
	n.Name = path.Base(to)
	n.AttackerWritten = true
	toParent.children[n.Name] = n
	return nil
}

// Chmod sets the permission bits on an existing entry.
func (f *FS) Chmod(p string, mode uint32) error {
	n, err := f.lookup(p, true)
	if err != nil {
		return err
	}
	n.Mode = mode
	n.AttackerWritten = true
	return nil
}

// Touch updates mtime, creating an empty file when absent.
func (f *FS) Touch(p string, uid, gid int) error {
	n, err := f.lookup(p, true)
	if err != nil {
		return f.WriteFile(p, nil, 0o644, uid, gid)
	}
	n.ModTime = time.Now()
	return nil
}

// AttackerFiles walks the tree and returns the paths of everything created or
// modified during this session. Used at session close to enumerate droppings.
func (f *FS) AttackerFiles() []string {
	var out []string
	var walk func(n *Node, prefix string)
	walk = func(n *Node, prefix string) {
		for name, c := range n.children {
			p := prefix + "/" + name
			if c.AttackerWritten {
				out = append(out, p)
			}
			if c.Kind == KindDir {
				walk(c, p)
			}
		}
	}
	walk(f.root, "")
	sort.Strings(out)
	return out
}

// Size reports a node's apparent size, evaluating dynamic content.
func (n *Node) Size() int64 {
	if n.Kind == KindDir {
		return 4096
	}
	if n.dynamic != nil {
		return int64(len(n.dynamic()))
	}
	return int64(len(n.content))
}

// Content returns raw stored bytes without evaluating dynamic files. Used by
// the session reporter when hashing attacker droppings.
func (n *Node) Content() []byte { return n.content }

// ModeString renders the ls-style permission column, e.g. "-rwxr-xr-x".
func (n *Node) ModeString() string {
	var b strings.Builder
	switch n.Kind {
	case KindDir:
		b.WriteByte('d')
	case KindSymlink:
		b.WriteByte('l')
	default:
		b.WriteByte('-')
	}
	perms := []struct {
		bit  uint32
		char byte
	}{
		{0o400, 'r'}, {0o200, 'w'}, {0o100, 'x'},
		{0o040, 'r'}, {0o020, 'w'}, {0o010, 'x'},
		{0o004, 'r'}, {0o002, 'w'}, {0o001, 'x'},
	}
	for _, p := range perms {
		if n.Mode&p.bit != 0 {
			b.WriteByte(p.char)
		} else {
			b.WriteByte('-')
		}
	}
	s := []byte(b.String())
	if n.Mode&0o1000 != 0 { // sticky
		if s[9] == 'x' {
			s[9] = 't'
		} else {
			s[9] = 'T'
		}
	}
	return string(s)
}

// ---- construction helpers ----

func (f *FS) mkdirAll(p string, mode uint32, uid, gid int, mt time.Time) {
	cur := f.root
	for _, part := range split(p) {
		next, ok := cur.children[part]
		if !ok {
			next = dir(part, mode, uid, gid, mt)
			cur.children[part] = next
		}
		cur = next
	}
}

func (f *FS) put(p string, n *Node) {
	f.mkdirAll(path.Dir(p), 0o755, 0, 0, f.p.BootTime)
	parent, err := f.lookup(path.Dir(p), true)
	if err != nil {
		return
	}
	parent.children[n.Name] = n
}

func (f *FS) chmodNode(p string, mode uint32) {
	if n, err := f.lookup(p, false); err == nil {
		n.Mode = mode
	}
}
