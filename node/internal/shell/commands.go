package shell

import (
	"crypto/md5"  //nolint:gosec // emulating md5sum output, not securing anything
	"crypto/sha1" //nolint:gosec // emulating sha1sum output
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/honeynet/node/internal/vfs"
)

// runStage dispatches a single command. It returns the command's stdout and an
// exit status. Nothing here executes anything -- every branch is a canned or
// VFS-derived response.
func (s *Shell) runStage(st Stage, stdin string) (string, int) {
	argv := st.Argv
	if len(argv) == 0 {
		return "", 0
	}

	// Strip a leading env-assignment prefix ("FOO=bar cmd ...") and absolute
	// or relative path components, so `/bin/busybox`, `./busybox` and
	// `busybox` all reach the same handler.
	for len(argv) > 0 && strings.Contains(argv[0], "=") && !strings.HasPrefix(argv[0], "-") {
		kv := strings.SplitN(argv[0], "=", 2)
		if strings.ContainsAny(kv[0], "/ ") {
			break
		}
		s.env[kv[0]] = kv[1]
		argv = argv[1:]
	}
	if len(argv) == 0 {
		return "", 0
	}

	full := argv[0]
	name := path.Base(full)
	args := argv[1:]

	if fn, ok := builtins[name]; ok {
		return fn(s, name, args, stdin)
	}

	// An explicit path that does not resolve in the VFS gets the error a real
	// shell gives, which differs from the not-found message for a bare name.
	if strings.Contains(full, "/") {
		if !s.fs.Exists(vfs.Clean(s.cwd, full)) {
			return fmt.Sprintf("bash: %s: No such file or directory\n", full), 127
		}
		return fmt.Sprintf("bash: %s: Permission denied\n", full), 126
	}
	return fmt.Sprintf("bash: %s: command not found\n", name), 127
}

type builtin func(s *Shell, name string, args []string, stdin string) (string, int)

var builtins map[string]builtin

// init populates the dispatch table. Declared here rather than as a literal so
// that handlers can reference builtins recursively (busybox re-dispatches).
func init() {
	builtins = map[string]builtin{
		"ls": cmdLS, "dir": cmdLS, "vdir": cmdLS,
		"cd": cmdCD, "pwd": cmdPWD,
		"cat": cmdCat, "head": cmdHead, "tail": cmdTail,
		"echo": cmdEcho, "printf": cmdEcho,
		"whoami": cmdWhoami, "id": cmdID, "groups": cmdGroups,
		"uname": cmdUname, "hostname": cmdHostname,
		"ps": cmdPS, "top": cmdTop, "htop": cmdTop,
		"netstat": cmdNetstat, "ss": cmdNetstat,
		"ifconfig": cmdIfconfig, "ip": cmdIP,
		"w": cmdW, "who": cmdWho, "users": cmdUsers, "last": cmdLast,
		"uptime": cmdUptime, "free": cmdFree, "df": cmdDF, "du": cmdDU,
		"nproc": cmdNproc, "lscpu": cmdLscpu,
		"wget": cmdWget, "curl": cmdCurl, "tftp": cmdTFTP,
		"nc": cmdNetcat, "netcat": cmdNetcat, "ftp": cmdFTP,
		"chmod": cmdChmod, "chown": cmdChown, "chgrp": cmdChown,
		"rm": cmdRM, "mkdir": cmdMkdir, "rmdir": cmdRmdir,
		"touch": cmdTouch, "mv": cmdMV, "cp": cmdCP, "ln": cmdLN,
		"history": cmdHistory, "crontab": cmdCrontab,
		"busybox": cmdBusybox,
		"which":   cmdWhich, "whereis": cmdWhereis, "type": cmdWhich,
		"grep": cmdGrep, "egrep": cmdGrep, "fgrep": cmdGrep,
		"wc": cmdWC, "sort": cmdSort, "uniq": cmdUniq, "cut": cmdCut,
		"tr": cmdTR, "sed": cmdSed, "awk": cmdAwk, "tee": cmdTee,
		"sleep": cmdSleep, "true": cmdTrue, "false": cmdFalse,
		"export": cmdExport, "env": cmdEnv, "set": cmdEnv, "unset": cmdUnset,
		"exit": cmdExit, "logout": cmdExit, "quit": cmdExit,
		"su": cmdSU, "sudo": cmdSudo, "passwd": cmdPasswd,
		"kill": cmdKill, "killall": cmdKill, "pkill": cmdKill, "pgrep": cmdPgrep,
		"find": cmdFind, "stat": cmdStat, "file": cmdFile, "readlink": cmdReadlink,
		"md5sum": cmdHash, "sha1sum": cmdHash, "sha256sum": cmdHash, "cksum": cmdHash,
		"mount": cmdMount, "lsof": cmdLsof, "dmesg": cmdDmesg,
		"service": cmdService, "systemctl": cmdSystemctl,
		"apt": cmdApt, "apt-get": cmdApt, "yum": cmdApt, "dnf": cmdApt,
		"dpkg": cmdDpkg, "rpm": cmdDpkg,
		"python": cmdInterp, "python3": cmdInterp, "perl": cmdInterp,
		"gcc": cmdInterp, "cc": cmdInterp, "make": cmdInterp,
		"nohup": cmdNohup, "timeout": cmdNohup, "watch": cmdNohup,
		"dd": cmdDD, "tar": cmdTar, "unzip": cmdUnzip, "gzip": cmdGzip,
		"basename": cmdBasename, "dirname": cmdDirname, "realpath": cmdRealpath,
		"date": cmdDate, "sync": cmdTrue, "clear": cmdClear, "reset": cmdClear,
		"mesg": cmdTrue, "tty": cmdTTY, "stty": cmdTrue, "umask": cmdUmask,
		"reboot": cmdReboot, "shutdown": cmdReboot, "poweroff": cmdReboot,
		"halt": cmdReboot, "init": cmdReboot,
		"scp": cmdSCP, "ssh": cmdSSH, "sftp": cmdSCP,
		"xargs": cmdXargs, "yes": cmdYes, "seq": cmdSeq,
		"base64": cmdBase64, "xxd": cmdXXD, "strings": cmdStrings,
		"iptables": cmdIptables, "sysctl": cmdSysctl,
		"useradd": cmdUseradd, "adduser": cmdUseradd, "userdel": cmdUseradd,
		"usermod": cmdUseradd, "groupadd": cmdUseradd,
		"nano": cmdEditor, "vi": cmdEditor, "vim": cmdEditor, "emacs": cmdEditor,
		"more": cmdCat, "less": cmdCat, "zcat": cmdCat,
		"shred": cmdRM, "wipe": cmdRM,
	}
}

// ---- helpers ----

func (s *Shell) userByUID(uid int) string {
	for _, u := range s.p.Users {
		if u.UID == uid {
			return u.Name
		}
	}
	switch uid {
	case 0:
		return "root"
	case 33:
		return "www-data"
	case 65534:
		return "nobody"
	}
	return strconv.Itoa(uid)
}

func hasFlag(args []string, flags ...string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		for _, f := range flags {
			if a == f {
				return true
			}
			// Bundled short flags: -la contains -l and -a.
			if len(f) == 2 && !strings.HasPrefix(a, "--") && strings.Contains(a[1:], f[1:]) {
				return true
			}
		}
	}
	return false
}

func operands(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" {
			out = append(out, a)
		}
	}
	return out
}

// ---- filesystem commands ----

func cmdLS(s *Shell, _ string, args []string, _ string) (string, int) {
	long := hasFlag(args, "-l")
	all := hasFlag(args, "-a", "--all")
	human := hasFlag(args, "-h")
	one := hasFlag(args, "-1")

	targets := operands(args)
	if len(targets) == 0 {
		targets = []string{"."}
	}

	var out strings.Builder
	code := 0
	for ti, t := range targets {
		p := vfs.Clean(s.cwd, t)
		if len(targets) > 1 {
			if ti > 0 {
				out.WriteString("\n")
			}
			fmt.Fprintf(&out, "%s:\n", t)
		}

		n, err := s.fs.Stat(p)
		if err != nil {
			fmt.Fprintf(&out, "ls: cannot access '%s': No such file or directory\n", t)
			code = 2
			continue
		}

		var entries []*vfs.Node
		if n.Kind == vfs.KindDir {
			entries, _ = s.fs.ReadDir(p)
		} else {
			entries = []*vfs.Node{n}
		}

		if long {
			total := 0
			for _, e := range entries {
				total += int(e.Size()+1023) / 1024 * 4
			}
			fmt.Fprintf(&out, "total %d\n", total)
		}

		var names []string
		for _, e := range entries {
			if !all && strings.HasPrefix(e.Name, ".") {
				continue
			}
			if long {
				size := fmt.Sprint(e.Size())
				if human {
					size = humanBytes(e.Size())
				}
				stamp := e.ModTime.Format("Jan  2 15:04")
				if time.Since(e.ModTime) > 180*24*time.Hour {
					stamp = e.ModTime.Format("Jan  2  2006")
				}
				link := ""
				if e.Kind == vfs.KindSymlink {
					link = " -> " + e.Target
				}
				links := 1
				if e.Kind == vfs.KindDir {
					links = 2
				}
				fmt.Fprintf(&out, "%s %d %-8s %-8s %8s %s %s%s\n",
					e.ModeString(), links, s.userByUID(e.UID), s.userByUID(e.GID),
					size, stamp, e.Name, link)
			} else {
				names = append(names, e.Name)
			}
		}

		if !long && len(names) > 0 {
			if one {
				out.WriteString(strings.Join(names, "\n") + "\n")
			} else {
				out.WriteString(columnize(names))
			}
		}
	}
	return out.String(), code
}

// columnize renders names in the multi-column layout ls uses on an 80-column
// terminal.
func columnize(names []string) string {
	if len(names) == 0 {
		return ""
	}
	width := 0
	for _, n := range names {
		if len(n) > width {
			width = len(n)
		}
	}
	width += 2
	perRow := 80 / width
	if perRow < 1 {
		perRow = 1
	}
	var b strings.Builder
	for i, n := range names {
		if i > 0 && i%perRow == 0 {
			b.WriteString("\n")
		}
		if (i+1)%perRow == 0 || i == len(names)-1 {
			b.WriteString(n)
		} else {
			fmt.Fprintf(&b, "%-*s", width, n)
		}
	}
	b.WriteString("\n")
	return b.String()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}

func cmdCD(s *Shell, _ string, args []string, _ string) (string, int) {
	target := s.env["HOME"]
	if ops := operands(args); len(ops) > 0 {
		target = ops[0]
	}
	if target == "-" {
		target = s.env["OLDPWD"]
		if target == "" {
			return "bash: cd: OLDPWD not set\n", 1
		}
	}
	p := vfs.Clean(s.cwd, target)
	n, err := s.fs.Stat(p)
	if err != nil {
		return fmt.Sprintf("bash: cd: %s: No such file or directory\n", target), 1
	}
	if n.Kind != vfs.KindDir {
		return fmt.Sprintf("bash: cd: %s: Not a directory\n", target), 1
	}
	s.env["OLDPWD"] = s.cwd
	s.cwd = p
	s.env["PWD"] = p
	return "", 0
}

func cmdPWD(s *Shell, _ string, _ []string, _ string) (string, int) {
	return s.cwd + "\n", 0
}

func cmdCat(s *Shell, name string, args []string, stdin string) (string, int) {
	files := operands(args)
	if len(files) == 0 {
		return stdin, 0
	}
	var out strings.Builder
	code := 0
	for _, f := range files {
		p := vfs.Clean(s.cwd, f)

		// /etc/shadow and friends are unreadable to non-root. The denial is
		// itself signal: it tells us the actor checked their privilege level.
		if n, err := s.fs.Stat(p); err == nil && s.uid != 0 && n.Mode&0o004 == 0 && n.UID != s.uid {
			fmt.Fprintf(&out, "%s: %s: Permission denied\n", name, f)
			code = 1
			continue
		}
		data, err := s.fs.ReadFile(p)
		if err != nil {
			switch {
			case err == vfs.ErrIsDir:
				fmt.Fprintf(&out, "%s: %s: Is a directory\n", name, f)
			default:
				fmt.Fprintf(&out, "%s: %s: No such file or directory\n", name, f)
			}
			code = 1
			continue
		}
		out.Write(data)
	}
	return out.String(), code
}

func cmdHead(s *Shell, _ string, args []string, stdin string) (string, int) {
	return headTail(s, args, stdin, true)
}

func cmdTail(s *Shell, _ string, args []string, stdin string) (string, int) {
	return headTail(s, args, stdin, false)
}

func headTail(s *Shell, args []string, stdin string, head bool) (string, int) {
	count := 10
	for i, a := range args {
		if a == "-n" && i+1 < len(args) {
			if v, err := strconv.Atoi(args[i+1]); err == nil {
				count = v
			}
		} else if strings.HasPrefix(a, "-n") && len(a) > 2 {
			if v, err := strconv.Atoi(a[2:]); err == nil {
				count = v
			}
		} else if strings.HasPrefix(a, "-") && len(a) > 1 {
			if v, err := strconv.Atoi(a[1:]); err == nil {
				count = v
			}
		}
	}

	content := stdin
	var skipNext bool
	for _, f := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if f == "-n" {
			skipNext = true
			continue
		}
		if strings.HasPrefix(f, "-") {
			continue
		}
		data, err := s.fs.ReadFile(vfs.Clean(s.cwd, f))
		if err != nil {
			return fmt.Sprintf("head: cannot open '%s' for reading: No such file or directory\n", f), 1
		}
		content = string(data)
		break
	}

	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return "", 0
	}
	if count > len(lines) {
		count = len(lines)
	}
	if head {
		return strings.Join(lines[:count], "\n") + "\n", 0
	}
	return strings.Join(lines[len(lines)-count:], "\n") + "\n", 0
}

func cmdEcho(s *Shell, name string, args []string, _ string) (string, int) {
	noNewline := false
	interpret := name == "printf"
	var parts []string

	for i, a := range args {
		if i == 0 || len(parts) == 0 {
			if a == "-n" {
				noNewline = true
				continue
			}
			if a == "-e" {
				interpret = true
				continue
			}
			if a == "-ne" || a == "-en" {
				noNewline, interpret = true, true
				continue
			}
		}
		parts = append(parts, s.expand(a))
	}

	out := strings.Join(parts, " ")
	if interpret {
		out = unescape(out)
	}
	if !noNewline && name != "printf" {
		out += "\n"
	}
	return out, 0
}

// unescape resolves the escape forms `echo -e` understands. Loaders lean on
// \xNN heavily to smuggle binary payloads through a text channel, so getting
// this right is what lets us capture the dropped bytes rather than the
// obfuscated source line.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '0':
			b.WriteByte(0)
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'f':
			b.WriteByte(12)
		case 'v':
			b.WriteByte(11)
		case '\\':
			b.WriteByte('\\')
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 2
					continue
				}
			}
			b.WriteString("\\x")
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// expand substitutes $VAR and ${VAR} references from the session environment.
func (s *Shell) expand(str string) string {
	if !strings.Contains(str, "$") {
		return str
	}
	var b strings.Builder
	for i := 0; i < len(str); i++ {
		if str[i] != '$' || i+1 >= len(str) {
			b.WriteByte(str[i])
			continue
		}
		i++
		if str[i] == '{' {
			end := strings.IndexByte(str[i:], '}')
			if end < 0 {
				b.WriteString("${")
				continue
			}
			b.WriteString(s.env[str[i+1:i+end]])
			i += end
			continue
		}
		if str[i] == '?' {
			b.WriteString(strconv.Itoa(s.exitCode))
			continue
		}
		start := i
		for i < len(str) && (str[i] == '_' || str[i] >= 'A' && str[i] <= 'Z' ||
			str[i] >= 'a' && str[i] <= 'z' || str[i] >= '0' && str[i] <= '9') {
			i++
		}
		b.WriteString(s.env[str[start:i]])
		i--
	}
	return b.String()
}

// ---- identity commands ----

func cmdWhoami(s *Shell, _ string, _ []string, _ string) (string, int) {
	return s.user + "\n", 0
}

func cmdID(s *Shell, _ string, args []string, _ string) (string, int) {
	if hasFlag(args, "-u") {
		return strconv.Itoa(s.uid) + "\n", 0
	}
	if hasFlag(args, "-g") {
		return strconv.Itoa(s.gid) + "\n", 0
	}
	if hasFlag(args, "-un") {
		return s.user + "\n", 0
	}
	if s.uid == 0 {
		return "uid=0(root) gid=0(root) groups=0(root)\n", 0
	}
	return fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%d(%s),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)\n",
		s.uid, s.user, s.gid, s.user, s.gid, s.user), 0
}

func cmdGroups(s *Shell, _ string, _ []string, _ string) (string, int) {
	if s.uid == 0 {
		return "root\n", 0
	}
	return s.user + " adm cdrom sudo dip plugdev\n", 0
}

func cmdUname(s *Shell, _ string, args []string, _ string) (string, int) {
	p := s.p
	if len(args) == 0 {
		return "Linux\n", 0
	}
	if hasFlag(args, "-a", "--all") {
		return fmt.Sprintf("Linux %s %s #1 SMP %s %s %s %s GNU/Linux\n",
			p.Hostname, p.KernelRel,
			p.BootTime.Format("Mon Jan 2 15:04:05 UTC 2006"),
			p.Arch, p.Arch, p.Arch), 0
	}
	var parts []string
	if hasFlag(args, "-s") {
		parts = append(parts, "Linux")
	}
	if hasFlag(args, "-n") {
		parts = append(parts, p.Hostname)
	}
	if hasFlag(args, "-r") {
		parts = append(parts, p.KernelRel)
	}
	if hasFlag(args, "-v") {
		parts = append(parts, "#1 SMP "+p.BootTime.Format("Mon Jan 2 15:04:05 UTC 2006"))
	}
	if hasFlag(args, "-m", "-p", "-i") {
		parts = append(parts, p.Arch)
	}
	if hasFlag(args, "-o") {
		parts = append(parts, "GNU/Linux")
	}
	if len(parts) == 0 {
		return "Linux\n", 0
	}
	return strings.Join(parts, " ") + "\n", 0
}

func cmdHostname(s *Shell, _ string, args []string, _ string) (string, int) {
	if hasFlag(args, "-I", "-i") {
		return s.p.InternalIP + " \n", 0
	}
	return s.p.Hostname + "\n", 0
}

// ---- process and system state ----

// procTable renders a plausible process list. Entries are derived from the
// personality's package list so that a box with nginx installed also shows
// nginx workers -- an inconsistency there is a cheap tell.
func (s *Shell) procTable() []procEntry {
	base := []procEntry{
		{1, 0, "root", 0.0, 0.4, 168404, 13140, "?", "Ss", "/sbin/init"},
		{2, 0, "root", 0.0, 0.0, 0, 0, "?", "S", "[kthreadd]"},
		{3, 2, "root", 0.0, 0.0, 0, 0, "?", "I<", "[rcu_gp]"},
		{9, 2, "root", 0.0, 0.0, 0, 0, "?", "I", "[rcu_sched]"},
		{11, 2, "root", 0.0, 0.0, 0, 0, "?", "S", "[migration/0]"},
		{14, 2, "root", 0.0, 0.0, 0, 0, "?", "S", "[ksoftirqd/0]"},
		{262, 1, "root", 0.0, 0.3, 47936, 10192, "?", "Ss", "/lib/systemd/systemd-journald"},
		{289, 1, "root", 0.0, 0.1, 22588, 5744, "?", "Ss", "/lib/systemd/systemd-udevd"},
		{512, 1, "systemd-resolve", 0.0, 0.2, 25404, 8320, "?", "Ss", "/lib/systemd/systemd-resolved"},
		{531, 1, "root", 0.0, 0.1, 9224, 2916, "?", "Ss", "/usr/sbin/cron -f"},
		{534, 1, "message+", 0.0, 0.1, 8460, 4188, "?", "Ss", "/usr/bin/dbus-daemon --system --address=systemd:"},
		{551, 1, "syslog", 0.0, 0.1, 222400, 4560, "?", "Ssl", "/usr/sbin/rsyslogd -n -iNONE"},
		{588, 1, "root", 0.0, 0.2, 15420, 7040, "?", "Ss", "/usr/sbin/sshd -D"},
		{601, 1, "root", 0.0, 0.0, 5828, 1780, "tty1", "Ss+", "/sbin/agetty -o -p -- \\u --noclear tty1 linux"},
	}

	pid := 900
	for _, pkg := range s.p.Packages {
		switch pkg {
		case "nginx":
			base = append(base,
				procEntry{pid, 1, "root", 0.0, 0.1, 55212, 1720, "?", "Ss", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"},
				procEntry{pid + 1, pid, "www-data", 0.0, 0.2, 55880, 6284, "?", "S", "nginx: worker process"})
			pid += 2
		case "apache2":
			base = append(base, procEntry{pid, 1, "root", 0.0, 0.5, 199212, 18420, "?", "Ss", "/usr/sbin/apache2 -k start"})
			pid++
		case "mysql-server", "mariadb-server":
			base = append(base, procEntry{pid, 1, "mysql", 0.3, 8.2, 1804552, 336180, "?", "Ssl", "/usr/sbin/mysqld"})
			pid++
		case "redis-server":
			base = append(base, procEntry{pid, 1, "redis", 0.1, 0.4, 66040, 12088, "?", "Ssl", "/usr/bin/redis-server 127.0.0.1:6379"})
			pid++
		case "postgresql":
			base = append(base, procEntry{pid, 1, "postgres", 0.0, 1.2, 214860, 49312, "?", "Ss", "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main"})
			pid++
		case "docker.io":
			base = append(base, procEntry{pid, 1, "root", 0.2, 2.1, 1892340, 86400, "?", "Ssl", "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock"})
			pid++
		case "fail2ban":
			base = append(base, procEntry{pid, 1, "root", 0.0, 0.6, 253180, 25640, "?", "Ssl", "/usr/bin/python3 /usr/bin/fail2ban-server -xf start"})
			pid++
		}
	}

	// The attacker's own session.
	base = append(base,
		procEntry{pid + 40, 588, "root", 0.0, 0.2, 17064, 8120, "?", "Ss", "sshd: " + s.user + " [priv]"},
		procEntry{pid + 41, pid + 40, s.user, 0.0, 0.1, 17064, 5240, "?", "S", "sshd: " + s.user + "@pts/0"},
		procEntry{pid + 42, pid + 41, s.user, 0.0, 0.1, 8352, 5124, "pts/0", "Ss", "-bash"},
		procEntry{pid + 55, pid + 42, s.user, 0.0, 0.0, 10096, 3260, "pts/0", "R+", "ps aux"},
	)
	return base
}

type procEntry struct {
	pid, ppid  int
	user       string
	cpu, mem   float64
	vsz, rss   int
	tty, stat  string
	cmd        string
}

func cmdPS(s *Shell, _ string, args []string, _ string) (string, int) {
	procs := s.procTable()
	wide := hasFlag(args, "-a", "-e", "-x", "-f", "-u") || len(args) == 0

	var b strings.Builder
	if hasFlag(args, "-f") && !hasFlag(args, "-u") {
		b.WriteString("UID          PID    PPID  C STIME TTY          TIME CMD\n")
		for _, p := range procs {
			if !wide && p.tty != "pts/0" {
				continue
			}
			fmt.Fprintf(&b, "%-12s %5d %7d  0 %s %-8s %s %s\n",
				p.user, p.pid, p.ppid, s.p.BootTime.Format("15:04"), p.tty, "00:00:00", p.cmd)
		}
		return b.String(), 0
	}

	if len(args) == 0 {
		b.WriteString("    PID TTY          TIME CMD\n")
		for _, p := range procs {
			if p.tty != "pts/0" {
				continue
			}
			fmt.Fprintf(&b, "%7d %-12s %s %s\n", p.pid, p.tty, "00:00:00", strings.Fields(p.cmd)[0])
		}
		return b.String(), 0
	}

	b.WriteString("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
	for _, p := range procs {
		fmt.Fprintf(&b, "%-12s %5d %4.1f %4.1f %6d %5d %-8s %-4s %5s %6s %s\n",
			p.user, p.pid, p.cpu, p.mem, p.vsz, p.rss, p.tty, p.stat,
			s.p.BootTime.Format("Jan02"), "0:00", p.cmd)
	}
	return b.String(), 0
}

func cmdPgrep(s *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) == 0 {
		return "", 2
	}
	var b strings.Builder
	found := false
	for _, p := range s.procTable() {
		if strings.Contains(p.cmd, ops[0]) {
			fmt.Fprintf(&b, "%d\n", p.pid)
			found = true
		}
	}
	if !found {
		return "", 1
	}
	return b.String(), 0
}

func cmdTop(s *Shell, _ string, _ []string, _ string) (string, int) {
	procs := s.procTable()
	up := s.p.Uptime()
	var b strings.Builder
	fmt.Fprintf(&b, "top - %s up %s,  1 user,  load average: 0.02, 0.04, 0.01\n",
		time.Now().Format("15:04:05"), formatUptime(up))
	fmt.Fprintf(&b, "Tasks: %3d total,   1 running, %3d sleeping,   0 stopped,   0 zombie\n",
		len(procs), len(procs)-1)
	b.WriteString("%Cpu(s):  0.7 us,  0.3 sy,  0.0 ni, 98.8 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st\n")
	fmt.Fprintf(&b, "MiB Mem :%9.1f total,%9.1f free,%9.1f used,%9.1f buff/cache\n",
		float64(s.p.MemTotalKB)/1024, float64(s.p.MemTotalKB)/1024/8,
		float64(s.p.MemTotalKB)/1024*0.3, float64(s.p.MemTotalKB)/1024*0.27)
	fmt.Fprintf(&b, "MiB Swap:%9.1f total,%9.1f free,%9.1f used.%9.1f avail Mem\n\n",
		float64(s.p.SwapKB)/1024, float64(s.p.SwapKB)/1024, 0.0, float64(s.p.MemTotalKB)/1024*0.6)
	b.WriteString("    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n")
	for i, p := range procs {
		if i > 18 {
			break
		}
		fmt.Fprintf(&b, "%7d %-9s 20   0 %7d %6d %6d %s %5.1f %5.1f   0:00.%02d %s\n",
			p.pid, p.user, p.vsz, p.rss, p.rss/3, p.stat[:1], p.cpu, p.mem, i,
			strings.Fields(p.cmd)[0])
	}
	return b.String(), 0
}

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%d days, %2d:%02d", days, hours, mins)
	}
	return fmt.Sprintf("%2d:%02d", hours, mins)
}

func cmdUptime(s *Shell, _ string, _ []string, _ string) (string, int) {
	return fmt.Sprintf(" %s up %s,  1 user,  load average: 0.02, 0.04, 0.01\n",
		time.Now().Format("15:04:05"), formatUptime(s.p.Uptime())), 0
}

func cmdFree(s *Shell, _ string, args []string, _ string) (string, int) {
	div, unit := 1, "B"
	switch {
	case hasFlag(args, "-m"):
		div, unit = 1024, "Mi"
	case hasFlag(args, "-g"):
		div, unit = 1024*1024, "Gi"
	case hasFlag(args, "-k"):
		div, unit = 1, "Ki"
	case hasFlag(args, "-h"):
		div, unit = 1024, "Mi"
	}
	total := s.p.MemTotalKB / div
	free := total / 8
	buff := total / 4
	used := total - free - buff
	swap := s.p.SwapKB / div

	var b strings.Builder
	fmt.Fprintf(&b, "               total        used        free      shared  buff/cache   available\n")
	fmt.Fprintf(&b, "Mem:    %12d%12d%12d%12d%12d%12d\n", total, used, free, total/100, buff, free+buff)
	fmt.Fprintf(&b, "Swap:   %12d%12d%12d\n", swap, 0, swap)
	_ = unit
	return b.String(), 0
}

func cmdDF(s *Shell, _ string, args []string, _ string) (string, int) {
	human := hasFlag(args, "-h")
	totalKB := 41153856
	usedKB := 14082560
	availKB := totalKB - usedKB - 2400000

	fmtSize := func(kb int) string {
		if human {
			return humanBytes(int64(kb) * 1024)
		}
		return strconv.Itoa(kb)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Filesystem     %8s %8s %8s Use%% Mounted on\n", "Size", "Used", "Avail")
	fmt.Fprintf(&b, "udev           %8s %8s %8s   0%% /dev\n", fmtSize(s.p.MemTotalKB/2), fmtSize(0), fmtSize(s.p.MemTotalKB/2))
	fmt.Fprintf(&b, "tmpfs          %8s %8s %8s   1%% /run\n", fmtSize(s.p.MemTotalKB/10), fmtSize(1200), fmtSize(s.p.MemTotalKB/10-1200))
	fmt.Fprintf(&b, "/dev/vda1      %8s %8s %8s  %2d%% /\n", fmtSize(totalKB), fmtSize(usedKB), fmtSize(availKB), usedKB*100/totalKB)
	fmt.Fprintf(&b, "tmpfs          %8s %8s %8s   0%% /dev/shm\n", fmtSize(s.p.MemTotalKB/2), fmtSize(0), fmtSize(s.p.MemTotalKB/2))
	fmt.Fprintf(&b, "tmpfs          %8s %8s %8s   1%% /run/lock\n", fmtSize(5120), fmtSize(4), fmtSize(5116))
	return b.String(), 0
}

func cmdDU(s *Shell, _ string, args []string, _ string) (string, int) {
	target := "."
	if ops := operands(args); len(ops) > 0 {
		target = ops[0]
	}
	p := vfs.Clean(s.cwd, target)
	if !s.fs.Exists(p) {
		return fmt.Sprintf("du: cannot access '%s': No such file or directory\n", target), 1
	}
	return fmt.Sprintf("%d\t%s\n", 48, target), 0
}

func cmdNproc(s *Shell, _ string, _ []string, _ string) (string, int) {
	return strconv.Itoa(s.p.CPUCores) + "\n", 0
}

func cmdLscpu(s *Shell, _ string, _ []string, _ string) (string, int) {
	p := s.p
	var b strings.Builder
	fmt.Fprintf(&b, "Architecture:            %s\n", p.Arch)
	fmt.Fprintf(&b, "  CPU op-mode(s):        32-bit, 64-bit\n")
	fmt.Fprintf(&b, "  Byte Order:            Little Endian\n")
	fmt.Fprintf(&b, "CPU(s):                  %d\n", p.CPUCores)
	fmt.Fprintf(&b, "  On-line CPU(s) list:   0-%d\n", p.CPUCores-1)
	fmt.Fprintf(&b, "Vendor ID:               GenuineIntel\n")
	fmt.Fprintf(&b, "  Model name:            %s\n", p.CPUModel)
	fmt.Fprintf(&b, "    CPU family:          6\n")
	fmt.Fprintf(&b, "    Model:               79\n")
	fmt.Fprintf(&b, "    Thread(s) per core:  1\n")
	fmt.Fprintf(&b, "    Core(s) per socket:  %d\n", p.CPUCores)
	fmt.Fprintf(&b, "    Socket(s):           1\n")
	fmt.Fprintf(&b, "    CPU max MHz:         %.4f\n", p.CPUMHz)
	fmt.Fprintf(&b, "    BogoMIPS:            %.2f\n", p.CPUMHz*2)
	fmt.Fprintf(&b, "Hypervisor vendor:       KVM\n")
	fmt.Fprintf(&b, "Virtualization type:     full\n")
	return b.String(), 0
}

// ---- network state ----

func cmdNetstat(s *Shell, _ string, _ []string, _ string) (string, int) {
	var b strings.Builder
	b.WriteString("Active Internet connections (servers and established)\n")
	b.WriteString("Proto Recv-Q Send-Q Local Address           Foreign Address         State\n")
	b.WriteString("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n")
	b.WriteString("tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN\n")
	for _, pkg := range s.p.Packages {
		switch pkg {
		case "nginx", "apache2":
			b.WriteString("tcp6       0      0 :::80                   :::*                    LISTEN\n")
			b.WriteString("tcp6       0      0 :::443                  :::*                    LISTEN\n")
		case "mysql-server", "mariadb-server":
			b.WriteString("tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n")
		case "redis-server":
			b.WriteString("tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN\n")
		case "postgresql":
			b.WriteString("tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN\n")
		}
	}
	fmt.Fprintf(&b, "tcp        0    336 %s:22          %s:%d      ESTABLISHED\n",
		s.p.InternalIP, "203.0.113.42", 51234)
	b.WriteString("udp        0      0 127.0.0.53:53           0.0.0.0:*                          \n")
	return b.String(), 0
}

func cmdIfconfig(s *Shell, _ string, _ []string, _ string) (string, int) {
	p := s.p
	var b strings.Builder
	fmt.Fprintf(&b, "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n")
	fmt.Fprintf(&b, "        inet %s  netmask 255.255.240.0  broadcast %s\n",
		p.InternalIP, strings.Join(append(strings.Split(p.InternalIP, ".")[:3], "255"), "."))
	fmt.Fprintf(&b, "        inet6 fe80::%s  prefixlen 64  scopeid 0x20<link>\n", p.MachineID()[:12])
	fmt.Fprintf(&b, "        ether %s  txqueuelen 1000  (Ethernet)\n", p.MACAddr)
	fmt.Fprintf(&b, "        RX packets %d  bytes %d (%s)\n", 1284739, 892374619, humanBytes(892374619))
	fmt.Fprintf(&b, "        RX errors 0  dropped 0  overruns 0  frame 0\n")
	fmt.Fprintf(&b, "        TX packets %d  bytes %d (%s)\n", 998231, 143829471, humanBytes(143829471))
	fmt.Fprintf(&b, "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n")
	fmt.Fprintf(&b, "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n")
	fmt.Fprintf(&b, "        inet 127.0.0.1  netmask 255.0.0.0\n")
	fmt.Fprintf(&b, "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n")
	fmt.Fprintf(&b, "        loop  txqueuelen 1000  (Local Loopback)\n")
	fmt.Fprintf(&b, "        RX packets 4821  bytes 412839 (412.8 KB)\n")
	fmt.Fprintf(&b, "        RX errors 0  dropped 0  overruns 0  frame 0\n")
	fmt.Fprintf(&b, "        TX packets 4821  bytes 412839 (412.8 KB)\n")
	fmt.Fprintf(&b, "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n")
	return b.String(), 0
}

func cmdIP(s *Shell, _ string, args []string, _ string) (string, int) {
	p := s.p
	sub := ""
	if ops := operands(args); len(ops) > 0 {
		sub = ops[0]
	}
	switch {
	case strings.HasPrefix(sub, "a"): // addr / a / address
		var b strings.Builder
		b.WriteString("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n")
		b.WriteString("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
		b.WriteString("    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n")
		fmt.Fprintf(&b, "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n")
		fmt.Fprintf(&b, "    link/ether %s brd ff:ff:ff:ff:ff:ff\n", p.MACAddr)
		fmt.Fprintf(&b, "    inet %s/20 brd %s scope global dynamic eth0\n",
			p.InternalIP, strings.Join(append(strings.Split(p.InternalIP, ".")[:3], "255"), "."))
		b.WriteString("       valid_lft 2591875sec preferred_lft 2591875sec\n")
		return b.String(), 0
	case strings.HasPrefix(sub, "r"): // route
		gw := strings.Join(append(strings.Split(p.InternalIP, ".")[:3], "1"), ".")
		return fmt.Sprintf("default via %s dev eth0 proto dhcp src %s metric 100\n%s/20 dev eth0 proto kernel scope link src %s\n",
			gw, p.InternalIP, strings.Join(append(strings.Split(p.InternalIP, ".")[:3], "0"), "."), p.InternalIP), 0
	}
	return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n", 1
}

// ---- login records ----

func cmdW(s *Shell, _ string, _ []string, _ string) (string, int) {
	var b strings.Builder
	fmt.Fprintf(&b, " %s up %s,  1 user,  load average: 0.02, 0.04, 0.01\n",
		time.Now().Format("15:04:05"), formatUptime(s.p.Uptime()))
	b.WriteString("USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n")
	fmt.Fprintf(&b, "%-8s pts/0    %-16s %-8s %4s  %5s  %5s w\n",
		s.user, "10.0.0.14", s.loginTime.Format("15:04"), "0.00s", "0.04s", "0.00s")
	return b.String(), 0
}

func cmdWho(s *Shell, _ string, _ []string, _ string) (string, int) {
	return fmt.Sprintf("%-8s pts/0        %s (10.0.0.14)\n",
		s.user, s.loginTime.Format("2006-01-02 15:04")), 0
}

func cmdUsers(s *Shell, _ string, _ []string, _ string) (string, int) {
	return s.user + "\n", 0
}

func cmdLast(s *Shell, _ string, _ []string, _ string) (string, int) {
	var b strings.Builder
	fmt.Fprintf(&b, "%-8s pts/0        10.0.0.14        %s   still logged in\n",
		s.user, s.loginTime.Format("Mon Jan  2 15:04"))
	fmt.Fprintf(&b, "reboot   system boot  %-16s %s   still running\n",
		s.p.KernelRel, s.p.BootTime.Format("Mon Jan  2 15:04"))
	fmt.Fprintf(&b, "\nwtmp begins %s\n", s.p.BootTime.Add(-72*time.Hour).Format("Mon Jan  2 15:04:05 2006"))
	return b.String(), 0
}

// ---- fetch tools: record, never retrieve ----
//
// These are the highest-value commands in the whole emulator. The URL is the
// IOC and the transcript is the campaign fingerprint. What the node must never
// do is actually open the connection -- see design doc section 4.2.

func cmdWget(s *Shell, _ string, args []string, _ string) (string, int) {
	urls := ExtractURLs(args)
	if len(urls) == 0 {
		return "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n", 1
	}

	quiet := hasFlag(args, "-q", "--quiet")
	var b strings.Builder
	for _, u := range urls {
		host, file := urlParts(u)
		outName := file
		for i, a := range args {
			if (a == "-O" || a == "--output-document") && i+1 < len(args) {
				outName = args[i+1]
			}
		}

		// Materialise the "downloaded" file so a follow-up `chmod +x` and
		// `./file` behave as the attacker expects and the chain keeps going.
		size := 41328 + len(u)*13
		_ = s.fs.WriteFile(vfs.Clean(s.cwd, outName),
			[]byte(strings.Repeat("\x00", 64)), 0o644, s.uid, s.gid)

		if quiet {
			continue
		}
		now := time.Now()
		fmt.Fprintf(&b, "--%s--  %s\n", now.Format("2006-01-02 15:04:05"), u)
		fmt.Fprintf(&b, "Resolving %s (%s)... %s\n", host, host, fakeResolve(host))
		fmt.Fprintf(&b, "Connecting to %s (%s)|%s|:80... connected.\n", host, host, fakeResolve(host))
		fmt.Fprintf(&b, "HTTP request sent, awaiting response... 200 OK\n")
		fmt.Fprintf(&b, "Length: %d (%s) [application/octet-stream]\n", size, humanBytes(int64(size)))
		fmt.Fprintf(&b, "Saving to: '%s'\n\n", outName)
		fmt.Fprintf(&b, "%-20s 100%%[===================>] %8s  --.-KB/s    in 0.1s\n\n",
			truncate(outName, 20), humanBytes(int64(size)))
		fmt.Fprintf(&b, "%s (%s) - '%s' saved [%d/%d]\n\n",
			now.Add(time.Second).Format("2006-01-02 15:04:05"),
			"412 KB/s", outName, size, size)
	}
	return b.String(), 0
}

func cmdCurl(s *Shell, _ string, args []string, _ string) (string, int) {
	urls := ExtractURLs(args)
	if len(urls) == 0 {
		return "curl: try 'curl --help' or 'curl --manual' for more information\n", 2
	}
	outName := ""
	for i, a := range args {
		if (a == "-o" || a == "--output") && i+1 < len(args) {
			outName = args[i+1]
		}
		if a == "-O" || a == "--remote-name" {
			_, outName = urlParts(urls[0])
		}
	}
	if outName != "" {
		_ = s.fs.WriteFile(vfs.Clean(s.cwd, outName),
			[]byte(strings.Repeat("\x00", 64)), 0o644, s.uid, s.gid)
		return "", 0
	}
	// Without -o curl writes the body to stdout. Emitting shell-shaped content
	// keeps a `curl ... | sh` chain moving, which is what we want to observe.
	return "", 0
}

func cmdTFTP(s *Shell, _ string, args []string, _ string) (string, int) {
	for i, a := range args {
		if (a == "-g" || a == "-r" || a == "-c") && i+1 < len(args) {
			_ = s.fs.WriteFile(vfs.Clean(s.cwd, path.Base(args[i+1])),
				[]byte(strings.Repeat("\x00", 64)), 0o644, s.uid, s.gid)
		}
	}
	return "", 0
}

func cmdFTP(_ *Shell, _ string, _ []string, _ string) (string, int) {
	return "ftp: connect: Connection timed out\n", 1
}

func cmdNetcat(_ *Shell, _ string, args []string, _ string) (string, int) {
	if hasFlag(args, "-l") {
		return "", 0
	}
	return "", 1
}

func urlParts(u string) (host, file string) {
	rest := u
	for _, s := range []string{"http://", "https://", "ftp://", "tftp://"} {
		rest = strings.TrimPrefix(rest, s)
	}
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return rest, "index.html"
	}
	host = rest[:slash]
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	file = path.Base(rest[slash:])
	if file == "" || file == "/" || file == "." {
		file = "index.html"
	}
	return host, file
}

// fakeResolve produces a stable pseudo-address for a hostname so repeated
// lookups in one session agree with each other.
func fakeResolve(host string) string {
	if strings.Count(host, ".") == 3 {
		if _, err := strconv.Atoi(strings.Split(host, ".")[0]); err == nil {
			return host
		}
	}
	sum := sha256.Sum256([]byte(host))
	return fmt.Sprintf("%d.%d.%d.%d", 20+int(sum[0])%200, sum[1], sum[2], 1+int(sum[3])%253)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// ---- file mutation ----

func cmdChmod(s *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) < 2 {
		return "chmod: missing operand\nTry 'chmod --help' for more information.\n", 1
	}
	mode := parseMode(ops[0])
	var out strings.Builder
	code := 0
	for _, f := range ops[1:] {
		if err := s.fs.Chmod(vfs.Clean(s.cwd, f), mode); err != nil {
			fmt.Fprintf(&out, "chmod: cannot access '%s': No such file or directory\n", f)
			code = 1
		}
	}
	return out.String(), code
}

func parseMode(s string) uint32 {
	if v, err := strconv.ParseUint(s, 8, 32); err == nil {
		return uint32(v)
	}
	// Symbolic forms. +x is overwhelmingly the common case in loader chains.
	if strings.Contains(s, "x") {
		return 0o755
	}
	if strings.Contains(s, "w") {
		return 0o666
	}
	return 0o644
}

func cmdChown(s *Shell, name string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) < 2 {
		return fmt.Sprintf("%s: missing operand\n", name), 1
	}
	if s.uid != 0 {
		return fmt.Sprintf("%s: changing ownership of '%s': Operation not permitted\n", name, ops[1]), 1
	}
	return "", 0
}

func cmdRM(s *Shell, name string, args []string, _ string) (string, int) {
	recursive := hasFlag(args, "-r", "-R", "--recursive")
	force := hasFlag(args, "-f", "--force")
	var out strings.Builder
	code := 0
	for _, f := range operands(args) {
		p := vfs.Clean(s.cwd, f)
		if err := s.fs.Remove(p, recursive); err != nil {
			if force {
				continue
			}
			switch err {
			case vfs.ErrNotEmpty:
				fmt.Fprintf(&out, "%s: cannot remove '%s': Is a directory\n", name, f)
			case vfs.ErrPermission:
				fmt.Fprintf(&out, "%s: cannot remove '%s': Permission denied\n", name, f)
			default:
				fmt.Fprintf(&out, "%s: cannot remove '%s': No such file or directory\n", name, f)
			}
			code = 1
		}
	}
	return out.String(), code
}

func cmdMkdir(s *Shell, _ string, args []string, _ string) (string, int) {
	parents := hasFlag(args, "-p", "--parents")
	var out strings.Builder
	code := 0
	for _, d := range operands(args) {
		p := vfs.Clean(s.cwd, d)
		var err error
		if parents {
			err = s.fs.MkdirAll(p, 0o755, s.uid, s.gid)
		} else {
			err = s.fs.Mkdir(p, 0o755, s.uid, s.gid)
		}
		if err != nil {
			fmt.Fprintf(&out, "mkdir: cannot create directory '%s': %s\n", d, errText(err))
			code = 1
		}
	}
	return out.String(), code
}

func errText(err error) string {
	switch err {
	case vfs.ErrExists:
		return "File exists"
	case vfs.ErrNotFound:
		return "No such file or directory"
	case vfs.ErrPermission:
		return "Permission denied"
	case vfs.ErrQuotaReached:
		return "No space left on device"
	case vfs.ErrNotDir:
		return "Not a directory"
	}
	return err.Error()
}

func cmdRmdir(s *Shell, _ string, args []string, _ string) (string, int) {
	var out strings.Builder
	code := 0
	for _, d := range operands(args) {
		if err := s.fs.Remove(vfs.Clean(s.cwd, d), false); err != nil {
			fmt.Fprintf(&out, "rmdir: failed to remove '%s': %s\n", d, errText(err))
			code = 1
		}
	}
	return out.String(), code
}

func cmdTouch(s *Shell, _ string, args []string, _ string) (string, int) {
	for _, f := range operands(args) {
		_ = s.fs.Touch(vfs.Clean(s.cwd, f), s.uid, s.gid)
	}
	return "", 0
}

func cmdMV(s *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) < 2 {
		return "mv: missing destination file operand\n", 1
	}
	from := vfs.Clean(s.cwd, ops[0])
	to := vfs.Clean(s.cwd, ops[1])
	if s.fs.IsDir(to) {
		to = path.Join(to, path.Base(from))
	}
	if err := s.fs.Rename(from, to); err != nil {
		return fmt.Sprintf("mv: cannot stat '%s': No such file or directory\n", ops[0]), 1
	}
	return "", 0
}

func cmdCP(s *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) < 2 {
		return "cp: missing destination file operand\n", 1
	}
	data, err := s.fs.ReadFile(vfs.Clean(s.cwd, ops[0]))
	if err != nil {
		return fmt.Sprintf("cp: cannot stat '%s': No such file or directory\n", ops[0]), 1
	}
	to := vfs.Clean(s.cwd, ops[1])
	if s.fs.IsDir(to) {
		to = path.Join(to, path.Base(ops[0]))
	}
	if err := s.fs.WriteFile(to, data, 0o644, s.uid, s.gid); err != nil {
		return fmt.Sprintf("cp: cannot create regular file '%s': %s\n", ops[1], errText(err)), 1
	}
	return "", 0
}

func cmdLN(s *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) < 2 {
		return "ln: missing file operand\n", 1
	}
	return "", 0
}

// ---- shell state ----

func cmdHistory(s *Shell, _ string, args []string, _ string) (string, int) {
	if hasFlag(args, "-c") {
		// The clear is honoured locally but the collector already holds every
		// line. Attackers wiping history is itself a recorded TTP (T1070.003).
		s.history = nil
		return "", 0
	}
	var b strings.Builder
	for i, h := range s.history {
		fmt.Fprintf(&b, "%5d  %s\n", i+1, h)
	}
	return b.String(), 0
}

func cmdCrontab(s *Shell, _ string, args []string, _ string) (string, int) {
	if hasFlag(args, "-l") {
		p := "/var/spool/cron/crontabs/" + s.user
		if data, err := s.fs.ReadFile(p); err == nil && len(data) > 0 {
			return string(data), 0
		}
		return fmt.Sprintf("no crontab for %s\n", s.user), 1
	}
	if hasFlag(args, "-r") {
		_ = s.fs.Remove("/var/spool/cron/crontabs/"+s.user, false)
		return "", 0
	}
	return "", 0
}

func cmdExport(s *Shell, _ string, args []string, _ string) (string, int) {
	for _, a := range args {
		if kv := strings.SplitN(a, "=", 2); len(kv) == 2 {
			s.env[kv[0]] = kv[1]
		}
	}
	return "", 0
}

func cmdEnv(s *Shell, _ string, _ []string, _ string) (string, int) {
	keys := make([]string, 0, len(s.env))
	for k := range s.env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, s.env[k])
	}
	return b.String(), 0
}

func cmdUnset(s *Shell, _ string, args []string, _ string) (string, int) {
	for _, a := range args {
		delete(s.env, a)
	}
	return "", 0
}

func cmdExit(s *Shell, _ string, _ []string, _ string) (string, int) {
	s.exitFlag = true
	return "logout\n", 0
}

func cmdClear(_ *Shell, _ string, _ []string, _ string) (string, int) {
	return "\x1b[H\x1b[2J\x1b[3J", 0
}

// ---- privilege ----

func cmdSU(s *Shell, _ string, args []string, _ string) (string, int) {
	if s.uid == 0 {
		target := "root"
		if ops := operands(args); len(ops) > 0 {
			target = ops[0]
		}
		s.user = target
		return "", 0
	}
	// A wrong-password delay is the single most fingerprinted timing in a
	// honeypot. Sourced from the personality so it is consistent per node.
	time.Sleep(time.Duration(s.p.AuthFailBaseMS) * time.Millisecond)
	return "su: Authentication failure\n", 1
}

func cmdSudo(s *Shell, _ string, args []string, stdin string) (string, int) {
	ops := operands(args)
	if len(ops) == 0 {
		return "usage: sudo -h | -K | -k | -V\n", 1
	}
	if s.uid == 0 {
		return s.runStage(Stage{Argv: ops}, stdin)
	}
	time.Sleep(time.Duration(s.p.AuthFailBaseMS) * time.Millisecond)
	return fmt.Sprintf("[sudo] password for %s: \nsudo: 1 incorrect password attempt\n", s.user), 1
}

func cmdPasswd(s *Shell, _ string, _ []string, _ string) (string, int) {
	return "Changing password for " + s.user + ".\nCurrent password: \npasswd: Authentication token manipulation error\npasswd: password unchanged\n", 1
}

func cmdKill(_ *Shell, name string, args []string, _ string) (string, int) {
	if len(operands(args)) == 0 {
		return fmt.Sprintf("%s: usage: %s [-s sigspec | -n signum | -sigspec] pid | jobspec ...\n", name, name), 2
	}
	return "", 0
}

// ---- inspection ----

func cmdWhich(s *Shell, name string, args []string, _ string) (string, int) {
	var b strings.Builder
	code := 0
	for _, a := range operands(args) {
		found := false
		for _, d := range strings.Split(s.env["PATH"], ":") {
			p := path.Join(d, a)
			if s.fs.Exists(p) {
				if name == "type" {
					fmt.Fprintf(&b, "%s is %s\n", a, p)
				} else {
					fmt.Fprintf(&b, "%s\n", p)
				}
				found = true
				break
			}
		}
		if !found {
			code = 1
			if name == "type" {
				fmt.Fprintf(&b, "bash: type: %s: not found\n", a)
			}
		}
	}
	return b.String(), code
}

func cmdWhereis(s *Shell, _ string, args []string, _ string) (string, int) {
	var b strings.Builder
	for _, a := range operands(args) {
		fmt.Fprintf(&b, "%s:", a)
		for _, d := range []string{"/bin", "/usr/bin", "/sbin", "/usr/sbin"} {
			if s.fs.Exists(path.Join(d, a)) {
				fmt.Fprintf(&b, " %s", path.Join(d, a))
			}
		}
		b.WriteString("\n")
	}
	return b.String(), 0
}

func cmdStat(s *Shell, _ string, args []string, _ string) (string, int) {
	var b strings.Builder
	code := 0
	for _, f := range operands(args) {
		p := vfs.Clean(s.cwd, f)
		n, err := s.fs.Stat(p)
		if err != nil {
			fmt.Fprintf(&b, "stat: cannot statx '%s': No such file or directory\n", f)
			code = 1
			continue
		}
		kind := "regular file"
		if n.Kind == vfs.KindDir {
			kind = "directory"
		}
		fmt.Fprintf(&b, "  File: %s\n", f)
		fmt.Fprintf(&b, "  Size: %-14d Blocks: %-10d IO Block: 4096   %s\n", n.Size(), (n.Size()+511)/512, kind)
		fmt.Fprintf(&b, "Device: 803h/2051d\tInode: %-10d Links: 1\n", 100000+len(f)*37)
		fmt.Fprintf(&b, "Access: (%04o/%s)  Uid: (%5d/%8s)   Gid: (%5d/%8s)\n",
			n.Mode&0o7777, n.ModeString(), n.UID, s.userByUID(n.UID), n.GID, s.userByUID(n.GID))
		fmt.Fprintf(&b, "Access: %s\nModify: %s\nChange: %s\n",
			n.ModTime.Format("2006-01-02 15:04:05.000000000 -0700"),
			n.ModTime.Format("2006-01-02 15:04:05.000000000 -0700"),
			n.ModTime.Format("2006-01-02 15:04:05.000000000 -0700"))
	}
	return b.String(), code
}

func cmdFile(s *Shell, _ string, args []string, _ string) (string, int) {
	var b strings.Builder
	for _, f := range operands(args) {
		p := vfs.Clean(s.cwd, f)
		n, err := s.fs.Stat(p)
		if err != nil {
			fmt.Fprintf(&b, "%s: cannot open `%s' (No such file or directory)\n", f, f)
			continue
		}
		switch {
		case n.Kind == vfs.KindDir:
			fmt.Fprintf(&b, "%s: directory\n", f)
		case n.Kind == vfs.KindSymlink:
			fmt.Fprintf(&b, "%s: symbolic link to %s\n", f, n.Target)
		case strings.HasPrefix(string(n.Content()), "\x7fELF"):
			fmt.Fprintf(&b, "%s: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=%s, for GNU/Linux 3.2.0, stripped\n",
				f, hex.EncodeToString([]byte(f))[:20])
		case n.Size() == 0:
			fmt.Fprintf(&b, "%s: empty\n", f)
		default:
			fmt.Fprintf(&b, "%s: ASCII text\n", f)
		}
	}
	return b.String(), 0
}

func cmdReadlink(s *Shell, _ string, args []string, _ string) (string, int) {
	for _, f := range operands(args) {
		n, err := s.fs.Lstat(vfs.Clean(s.cwd, f))
		if err != nil {
			return "", 1
		}
		if n.Kind == vfs.KindSymlink {
			return n.Target + "\n", 0
		}
		return vfs.Clean(s.cwd, f) + "\n", 0
	}
	return "", 1
}

func cmdHash(s *Shell, name string, args []string, stdin string) (string, int) {
	hashOf := func(data []byte) string {
		switch name {
		case "md5sum":
			sum := md5.Sum(data) //nolint:gosec // emulating md5sum
			return hex.EncodeToString(sum[:])
		case "sha1sum":
			sum := sha1.Sum(data) //nolint:gosec // emulating sha1sum
			return hex.EncodeToString(sum[:])
		default:
			sum := sha256.Sum256(data)
			return hex.EncodeToString(sum[:])
		}
	}
	files := operands(args)
	if len(files) == 0 {
		return hashOf([]byte(stdin)) + "  -\n", 0
	}
	var b strings.Builder
	code := 0
	for _, f := range files {
		data, err := s.fs.ReadFile(vfs.Clean(s.cwd, f))
		if err != nil {
			fmt.Fprintf(&b, "%s: %s: No such file or directory\n", name, f)
			code = 1
			continue
		}
		fmt.Fprintf(&b, "%s  %s\n", hashOf(data), f)
	}
	return b.String(), code
}

func cmdFind(s *Shell, _ string, args []string, _ string) (string, int) {
	root := "."
	if ops := operands(args); len(ops) > 0 {
		root = ops[0]
	}
	var namePat string
	for i, a := range args {
		if a == "-name" && i+1 < len(args) {
			namePat = strings.Trim(args[i+1], "*")
		}
	}
	start := vfs.Clean(s.cwd, root)
	if !s.fs.Exists(start) {
		return fmt.Sprintf("find: '%s': No such file or directory\n", root), 1
	}
	var b strings.Builder
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		if depth > 6 {
			return
		}
		entries, err := s.fs.ReadDir(p)
		if err != nil {
			return
		}
		for _, e := range entries {
			child := path.Join(p, e.Name)
			if namePat == "" || strings.Contains(e.Name, namePat) {
				fmt.Fprintf(&b, "%s\n", child)
			}
			if e.Kind == vfs.KindDir {
				walk(child, depth+1)
			}
		}
	}
	if namePat == "" {
		fmt.Fprintf(&b, "%s\n", start)
	}
	walk(start, 0)
	return b.String(), 0
}

// ---- text processing ----

func cmdGrep(s *Shell, _ string, args []string, stdin string) (string, int) {
	ops := operands(args)
	if len(ops) == 0 {
		return "Usage: grep [OPTION]... PATTERNS [FILE]...\n", 2
	}
	pattern := ops[0]
	invert := hasFlag(args, "-v")
	ignoreCase := hasFlag(args, "-i")
	countOnly := hasFlag(args, "-c")

	sources := map[string]string{}
	if len(ops) > 1 {
		for _, f := range ops[1:] {
			data, err := s.fs.ReadFile(vfs.Clean(s.cwd, f))
			if err != nil {
				continue
			}
			sources[f] = string(data)
		}
	} else {
		sources[""] = stdin
	}

	needle := pattern
	if ignoreCase {
		needle = strings.ToLower(pattern)
	}

	var b strings.Builder
	matched := 0
	multi := len(sources) > 1
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, fname := range names {
		count := 0
		for _, line := range strings.Split(sources[fname], "\n") {
			hay := line
			if ignoreCase {
				hay = strings.ToLower(line)
			}
			hit := strings.Contains(hay, needle)
			if hit == invert {
				continue
			}
			count++
			matched++
			if !countOnly {
				if multi {
					fmt.Fprintf(&b, "%s:%s\n", fname, line)
				} else {
					fmt.Fprintf(&b, "%s\n", line)
				}
			}
		}
		if countOnly {
			if multi {
				fmt.Fprintf(&b, "%s:%d\n", fname, count)
			} else {
				fmt.Fprintf(&b, "%d\n", count)
			}
		}
	}
	if matched == 0 {
		return b.String(), 1
	}
	return b.String(), 0
}

func cmdWC(s *Shell, _ string, args []string, stdin string) (string, int) {
	content := stdin
	files := operands(args)
	label := ""
	if len(files) > 0 {
		data, err := s.fs.ReadFile(vfs.Clean(s.cwd, files[0]))
		if err != nil {
			return fmt.Sprintf("wc: %s: No such file or directory\n", files[0]), 1
		}
		content = string(data)
		label = " " + files[0]
	}
	lines := strings.Count(content, "\n")
	words := len(strings.Fields(content))
	chars := len(content)

	switch {
	case hasFlag(args, "-l"):
		return fmt.Sprintf("%d%s\n", lines, label), 0
	case hasFlag(args, "-w"):
		return fmt.Sprintf("%d%s\n", words, label), 0
	case hasFlag(args, "-c"):
		return fmt.Sprintf("%d%s\n", chars, label), 0
	}
	return fmt.Sprintf("%7d %7d %7d%s\n", lines, words, chars, label), 0
}

func cmdSort(s *Shell, _ string, args []string, stdin string) (string, int) {
	content := stdin
	if files := operands(args); len(files) > 0 {
		if data, err := s.fs.ReadFile(vfs.Clean(s.cwd, files[0])); err == nil {
			content = string(data)
		}
	}
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	sort.Strings(lines)
	if hasFlag(args, "-r") {
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
	}
	if hasFlag(args, "-u") {
		lines = dedupe(lines)
	}
	return strings.Join(lines, "\n") + "\n", 0
}

func cmdUniq(_ *Shell, _ string, _ []string, stdin string) (string, int) {
	lines := strings.Split(strings.TrimSuffix(stdin, "\n"), "\n")
	var out []string
	for i, l := range lines {
		if i == 0 || l != lines[i-1] {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n") + "\n", 0
}

func dedupe(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func cmdCut(_ *Shell, _ string, args []string, stdin string) (string, int) {
	delim := "\t"
	fields := 1
	for i, a := range args {
		if strings.HasPrefix(a, "-d") {
			if len(a) > 2 {
				delim = strings.Trim(a[2:], "'\"")
			} else if i+1 < len(args) {
				delim = strings.Trim(args[i+1], "'\"")
			}
		}
		if strings.HasPrefix(a, "-f") {
			v := a[2:]
			if v == "" && i+1 < len(args) {
				v = args[i+1]
			}
			if n, err := strconv.Atoi(strings.SplitN(v, ",", 2)[0]); err == nil {
				fields = n
			}
		}
	}
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(stdin, "\n"), "\n") {
		parts := strings.Split(line, delim)
		if fields-1 < len(parts) {
			b.WriteString(parts[fields-1])
		}
		b.WriteString("\n")
	}
	return b.String(), 0
}

func cmdTR(_ *Shell, _ string, args []string, stdin string) (string, int) {
	ops := operands(args)
	if len(ops) < 2 {
		if hasFlag(args, "-d") && len(ops) == 1 {
			return strings.ReplaceAll(stdin, ops[0], ""), 0
		}
		return stdin, 0
	}
	from, to := ops[0], ops[1]
	if len(from) == len(to) {
		var pairs []string
		for i := range from {
			pairs = append(pairs, string(from[i]), string(to[i]))
		}
		return strings.NewReplacer(pairs...).Replace(stdin), 0
	}
	return stdin, 0
}

func cmdSed(_ *Shell, _ string, args []string, stdin string) (string, int) {
	ops := operands(args)
	if len(ops) == 0 {
		return stdin, 0
	}
	expr := ops[0]
	// Only s/// is supported. Anything else passes through unchanged, which is
	// wrong but quiet -- and quiet wrong beats an error that reveals emulation.
	if strings.HasPrefix(expr, "s") && len(expr) > 1 {
		sep := string(expr[1])
		parts := strings.Split(expr, sep)
		if len(parts) >= 3 {
			return strings.ReplaceAll(stdin, parts[1], parts[2]), 0
		}
	}
	return stdin, 0
}

func cmdAwk(_ *Shell, _ string, args []string, stdin string) (string, int) {
	ops := operands(args)
	if len(ops) == 0 {
		return "", 0
	}
	prog := strings.Trim(ops[0], "{} ")
	if !strings.HasPrefix(prog, "print") {
		return "", 0
	}
	spec := strings.TrimSpace(strings.TrimPrefix(prog, "print"))
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(stdin, "\n"), "\n") {
		f := strings.Fields(line)
		if spec == "" || spec == "$0" {
			b.WriteString(line + "\n")
			continue
		}
		if strings.HasPrefix(spec, "$") {
			if n, err := strconv.Atoi(spec[1:]); err == nil && n >= 1 && n <= len(f) {
				b.WriteString(f[n-1] + "\n")
			} else {
				b.WriteString("\n")
			}
		}
	}
	return b.String(), 0
}

func cmdTee(s *Shell, _ string, args []string, stdin string) (string, int) {
	for _, f := range operands(args) {
		p := vfs.Clean(s.cwd, f)
		if hasFlag(args, "-a") {
			_ = s.fs.Append(p, []byte(stdin), s.uid, s.gid)
		} else {
			_ = s.fs.WriteFile(p, []byte(stdin), 0o644, s.uid, s.gid)
		}
		if s.hooks.OnUpload != nil && stdin != "" {
			s.hooks.OnUpload(UploadEvent{Path: p, Content: []byte(stdin), ClaimedName: f, Transport: "tee"})
		}
	}
	return stdin, 0
}

func cmdXargs(s *Shell, _ string, args []string, stdin string) (string, int) {
	ops := operands(args)
	if len(ops) == 0 {
		return "", 0
	}
	argv := append(ops, strings.Fields(stdin)...)
	return s.runStage(Stage{Argv: argv}, "")
}

func cmdYes(_ *Shell, _ string, args []string, _ string) (string, int) {
	word := "y"
	if ops := operands(args); len(ops) > 0 {
		word = ops[0]
	}
	return strings.Repeat(word+"\n", 100), 0
}

func cmdSeq(_ *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	start, end := 1, 0
	switch len(ops) {
	case 1:
		end, _ = strconv.Atoi(ops[0])
	case 2:
		start, _ = strconv.Atoi(ops[0])
		end, _ = strconv.Atoi(ops[1])
	default:
		return "seq: missing operand\n", 1
	}
	if end-start > 10000 {
		end = start + 10000
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		fmt.Fprintf(&b, "%d\n", i)
	}
	return b.String(), 0
}

func cmdBase64(_ *Shell, _ string, args []string, stdin string) (string, int) {
	_ = args
	return stdin, 0
}

func cmdXXD(_ *Shell, _ string, _ []string, stdin string) (string, int) {
	var b strings.Builder
	data := []byte(stdin)
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(&b, "%08x: ", i)
		for j := i; j < i+16; j++ {
			if j < end {
				fmt.Fprintf(&b, "%02x", data[j])
			} else {
				b.WriteString("  ")
			}
			if (j-i)%2 == 1 {
				b.WriteString(" ")
			}
		}
		b.WriteString(" ")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] < 127 {
				b.WriteByte(data[j])
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("\n")
	}
	return b.String(), 0
}

func cmdStrings(s *Shell, _ string, args []string, stdin string) (string, int) {
	content := stdin
	if files := operands(args); len(files) > 0 {
		if data, err := s.fs.ReadFile(vfs.Clean(s.cwd, files[0])); err == nil {
			content = string(data)
		}
	}
	var b strings.Builder
	var cur strings.Builder
	for i := 0; i < len(content); i++ {
		c := content[i]
		if c >= 32 && c < 127 {
			cur.WriteByte(c)
			continue
		}
		if cur.Len() >= 4 {
			b.WriteString(cur.String() + "\n")
		}
		cur.Reset()
	}
	if cur.Len() >= 4 {
		b.WriteString(cur.String() + "\n")
	}
	return b.String(), 0
}

// ---- misc system ----

func cmdSleep(_ *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) == 0 {
		return "sleep: missing operand\n", 1
	}
	secs, err := strconv.ParseFloat(strings.TrimRight(ops[0], "smhd"), 64)
	if err != nil {
		return fmt.Sprintf("sleep: invalid time interval '%s'\n", ops[0]), 1
	}
	// Capped: a bot asking for `sleep 86400` must not pin a goroutine for a day.
	if secs > 10 {
		secs = 10
	}
	time.Sleep(time.Duration(secs * float64(time.Second)))
	return "", 0
}

func cmdTrue(_ *Shell, _ string, _ []string, _ string) (string, int)  { return "", 0 }
func cmdFalse(_ *Shell, _ string, _ []string, _ string) (string, int) { return "", 1 }

func cmdMount(s *Shell, _ string, _ []string, _ string) (string, int) {
	data, _ := s.fs.ReadFile("/proc/mounts")
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 {
			fmt.Fprintf(&b, "%s on %s type %s (%s)\n", f[0], f[1], f[2], f[3])
		}
	}
	return b.String(), 0
}

func cmdLsof(_ *Shell, _ string, _ []string, _ string) (string, int) {
	return "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n" +
		"sshd      588 root    3u  IPv4  15832      0t0  TCP *:ssh (LISTEN)\n", 0
}

func cmdDmesg(s *Shell, _ string, _ []string, _ string) (string, int) {
	if s.uid != 0 {
		return "dmesg: read kernel buffer failed: Operation not permitted\n", 1
	}
	p := s.p
	var b strings.Builder
	b.WriteString("[    0.000000] Linux version " + p.KernelRel + "\n")
	b.WriteString("[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-" + p.KernelRel + " root=UUID=" + p.MachineID()[:8] + " ro console=tty1 console=ttyS0\n")
	fmt.Fprintf(&b, "[    0.000000] KERNEL supported cpus:\n")
	fmt.Fprintf(&b, "[    0.004000] CPU: Physical Processor ID: 0\n")
	fmt.Fprintf(&b, "[    0.008000] Memory: %dK/%dK available\n", p.MemTotalKB-262144, p.MemTotalKB)
	b.WriteString("[    1.234567] virtio_net virtio0 eth0: renamed from eth0\n")
	b.WriteString("[    2.891234] EXT4-fs (vda1): mounted filesystem with ordered data mode.\n")
	return b.String(), 0
}

func cmdService(_ *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) < 2 {
		return "Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]\n", 1
	}
	return fmt.Sprintf(" * %sing %s\n   ...done.\n", strings.Title(ops[1]), ops[0]), 0 //nolint:staticcheck // matching sysvinit output
}

func cmdSystemctl(s *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) == 0 {
		return "", 0
	}
	switch ops[0] {
	case "status":
		if len(ops) < 2 {
			return "", 0
		}
		return fmt.Sprintf("● %s.service - %s\n     Loaded: loaded (/lib/systemd/system/%s.service; enabled; vendor preset: enabled)\n     Active: active (running) since %s; %s ago\n",
			ops[1], strings.Title(ops[1]), ops[1], //nolint:staticcheck // matching systemd output
			s.p.BootTime.Format("Mon 2006-01-02 15:04:05 UTC"), formatUptime(s.p.Uptime())), 0
	case "stop", "start", "restart", "disable", "enable", "mask":
		if s.uid != 0 {
			return "Failed to " + ops[0] + ": Interactive authentication required.\n", 1
		}
		return "", 0
	}
	return "", 0
}

func cmdApt(s *Shell, name string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) == 0 {
		return fmt.Sprintf("%s 2.4.11 (amd64)\nUsage: %s [options] command\n", name, name), 1
	}
	if s.uid != 0 {
		return fmt.Sprintf("E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n"), 100
	}
	switch ops[0] {
	case "update":
		return "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\nGet:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [128 kB]\nFetched 128 kB in 1s (128 kB/s)\nReading package lists... Done\n", 0
	case "install":
		var b strings.Builder
		b.WriteString("Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n")
		fmt.Fprintf(&b, "E: Unable to locate package %s\n", strings.Join(ops[1:], " "))
		return b.String(), 100
	}
	return "", 0
}

func cmdDpkg(s *Shell, name string, args []string, _ string) (string, int) {
	if hasFlag(args, "-l", "--list") || (len(args) > 0 && args[0] == "-qa") {
		var b strings.Builder
		if name == "dpkg" {
			b.WriteString("Desired=Unknown/Install/Remove/Purge/Hold\n")
			b.WriteString("| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n")
			b.WriteString("|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n")
			b.WriteString("||/ Name           Version      Architecture Description\n")
			b.WriteString("+++-==============-============-============-=================================\n")
		}
		pkgs := append([]string{}, s.p.Packages...)
		sort.Strings(pkgs)
		for _, p := range pkgs {
			if name == "dpkg" {
				fmt.Fprintf(&b, "ii  %-14s %-12s %-12s %s\n", p, "1.0-1ubuntu1", "amd64", p)
			} else {
				fmt.Fprintf(&b, "%s-1.0-1.x86_64\n", p)
			}
		}
		return b.String(), 0
	}
	return "", 0
}

func cmdInterp(_ *Shell, name string, args []string, _ string) (string, int) {
	// Scripting languages and compilers report a version but never run
	// anything. A loader that tries `python3 -c '...'` gets silence, which is
	// a plausible outcome on a locked-down box and keeps the session alive.
	if hasFlag(args, "--version", "-V", "-v") {
		switch name {
		case "python3", "python":
			return "Python 3.10.12\n", 0
		case "perl":
			return "This is perl 5, version 34, subversion 0 (v5.34.0) built for x86_64-linux-gnu-thread-multi\n", 0
		case "gcc", "cc":
			return "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0\nCopyright (C) 2021 Free Software Foundation, Inc.\n", 0
		case "make":
			return "GNU Make 4.3\nBuilt for x86_64-pc-linux-gnu\n", 0
		}
	}
	if name == "make" {
		return "make: *** No targets specified and no makefile found.  Stop.\n", 2
	}
	return "", 0
}

func cmdNohup(s *Shell, name string, args []string, stdin string) (string, int) {
	ops := operands(args)
	if name == "timeout" && len(ops) > 1 {
		ops = ops[1:]
	}
	if len(ops) == 0 {
		return "", 0
	}
	out, code := s.runStage(Stage{Argv: ops}, stdin)
	if name == "nohup" {
		return "nohup: ignoring input and appending output to 'nohup.out'\n" + out, code
	}
	return out, code
}

func cmdDD(s *Shell, _ string, args []string, _ string) (string, int) {
	var of string
	count, bs := 0, 512
	for _, a := range args {
		kv := strings.SplitN(a, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "of":
			of = kv[1]
		case "count":
			count, _ = strconv.Atoi(kv[1])
		case "bs":
			bs = parseSize(kv[1])
		}
	}
	total := count * bs
	if total > 1<<20 {
		total = 1 << 20
	}
	if of != "" {
		if err := s.fs.WriteFile(vfs.Clean(s.cwd, of), make([]byte, total), 0o644, s.uid, s.gid); err != nil {
			return fmt.Sprintf("dd: writing to '%s': %s\n", of, errText(err)), 1
		}
	}
	return fmt.Sprintf("%d+0 records in\n%d+0 records out\n%d bytes (%s) copied, 0.0123456 s, %s/s\n",
		count, count, total, humanBytes(int64(total)), humanBytes(int64(total)*80)), 0
}

func parseSize(s string) int {
	mult := 1
	switch {
	case strings.HasSuffix(s, "K"), strings.HasSuffix(s, "k"):
		mult, s = 1024, s[:len(s)-1]
	case strings.HasSuffix(s, "M"), strings.HasSuffix(s, "m"):
		mult, s = 1024*1024, s[:len(s)-1]
	}
	v, _ := strconv.Atoi(s)
	return v * mult
}

func cmdTar(_ *Shell, _ string, _ []string, _ string) (string, int)   { return "", 0 }
func cmdUnzip(_ *Shell, _ string, _ []string, _ string) (string, int) { return "", 0 }
func cmdGzip(_ *Shell, _ string, _ []string, _ string) (string, int)  { return "", 0 }

func cmdBasename(_ *Shell, _ string, args []string, _ string) (string, int) {
	if ops := operands(args); len(ops) > 0 {
		return path.Base(ops[0]) + "\n", 0
	}
	return "basename: missing operand\n", 1
}

func cmdDirname(_ *Shell, _ string, args []string, _ string) (string, int) {
	if ops := operands(args); len(ops) > 0 {
		return path.Dir(ops[0]) + "\n", 0
	}
	return "dirname: missing operand\n", 1
}

func cmdRealpath(s *Shell, _ string, args []string, _ string) (string, int) {
	if ops := operands(args); len(ops) > 0 {
		return vfs.Clean(s.cwd, ops[0]) + "\n", 0
	}
	return "realpath: missing operand\n", 1
}

func cmdDate(_ *Shell, _ string, args []string, _ string) (string, int) {
	now := time.Now().UTC()
	for _, a := range args {
		if strings.HasPrefix(a, "+%s") {
			return strconv.FormatInt(now.Unix(), 10) + "\n", 0
		}
	}
	return now.Format("Mon Jan  2 15:04:05 UTC 2006") + "\n", 0
}

func cmdTTY(s *Shell, _ string, _ []string, _ string) (string, int) {
	if s.pty {
		return "/dev/pts/0\n", 0
	}
	return "not a tty\n", 1
}

func cmdUmask(_ *Shell, _ string, _ []string, _ string) (string, int) { return "0022\n", 0 }

func cmdReboot(s *Shell, name string, _ []string, _ string) (string, int) {
	if s.uid != 0 {
		return fmt.Sprintf("%s: Operation not permitted\n", name), 1
	}
	// Pretend to accept, then drop the session. A real reboot would close the
	// connection, so this is the honest emulation -- and it ends a session that
	// has nothing more to teach us.
	s.exitFlag = true
	return "Connection to host closed by remote host.\n", 0
}

func cmdSCP(_ *Shell, name string, _ []string, _ string) (string, int) {
	return fmt.Sprintf("%s: Connection closed\n", name), 1
}

func cmdSSH(_ *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	target := "host"
	if len(ops) > 0 {
		target = ops[0]
	}
	return fmt.Sprintf("ssh: connect to host %s port 22: Connection timed out\n", target), 255
}

func cmdIptables(s *Shell, _ string, args []string, _ string) (string, int) {
	if s.uid != 0 {
		return "iptables v1.8.7 (nf_tables): Permission denied (you must be root)\n", 4
	}
	if hasFlag(args, "-L") {
		return "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\n\n" +
			"Chain FORWARD (policy ACCEPT)\ntarget     prot opt source               destination\n\n" +
			"Chain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination\n", 0
	}
	return "", 0
}

func cmdSysctl(s *Shell, _ string, args []string, _ string) (string, int) {
	ops := operands(args)
	if len(ops) == 0 {
		return "", 0
	}
	known := map[string]string{
		"kernel.hostname":               s.p.Hostname,
		"kernel.ostype":                 "Linux",
		"kernel.osrelease":              s.p.KernelRel,
		"net.ipv4.ip_forward":           "0",
		"vm.swappiness":                 "60",
		"kernel.randomize_va_space":     "2",
		"net.ipv4.tcp_syncookies":       "1",
		"fs.file-max":                   "9223372036854775807",
	}
	key := strings.SplitN(ops[0], "=", 2)[0]
	if v, ok := known[key]; ok {
		return fmt.Sprintf("%s = %s\n", key, v), 0
	}
	return fmt.Sprintf("sysctl: cannot stat /proc/sys/%s: No such file or directory\n",
		strings.ReplaceAll(key, ".", "/")), 255
}

func cmdUseradd(s *Shell, name string, _ []string, _ string) (string, int) {
	if s.uid != 0 {
		return fmt.Sprintf("%s: Permission denied.\n%s: cannot lock /etc/passwd; try again later.\n", name, name), 1
	}
	return "", 0
}

func cmdEditor(_ *Shell, name string, args []string, _ string) (string, int) {
	// Interactive editors would hang the session waiting for terminal control
	// sequences we do not emulate. Reporting a missing terminal is what a real
	// box does under a non-conforming TERM and costs us nothing.
	if len(operands(args)) == 0 {
		return fmt.Sprintf("%s: no file specified\n", name), 1
	}
	return fmt.Sprintf("%s: Vim: Warning: Output is not to a terminal\n", name), 1
}

// cmdBusybox handles the applet dispatcher.
//
// This command matters more than its size suggests. Mirai and its descendants
// probe with `/bin/busybox <NONSENSE>` and read the reply: a real busybox
// answers "<applet>: applet not found", and that exact string is how the loader
// confirms it has a live embedded target. Getting the format wrong -- or
// answering "command not found" -- ends the infection chain before the payload
// URL is ever disclosed, which is the one thing we most want to capture.
func cmdBusybox(s *Shell, _ string, args []string, stdin string) (string, int) {
	if len(args) == 0 {
		return "BusyBox v1.30.1 (2021-06-07 21:19:47 UTC) multi-call binary.\n" +
			"BusyBox is copyrighted by many authors between 1998-2015.\n" +
			"Licensed under GPLv2. See source distribution for detailed\n" +
			"copyright notices.\n\n" +
			"Usage: busybox [function [arguments]...]\n" +
			"   or: busybox --list\n\n" +
			"Currently defined functions:\n" +
			"\t[, [[, arch, ash, awk, base64, basename, cat, chgrp, chmod, chown,\n" +
			"\tcp, cut, date, dd, df, dmesg, echo, egrep, env, false, fgrep, find,\n" +
			"\tgrep, gunzip, gzip, head, hostname, id, ifconfig, kill, killall, ln,\n" +
			"\tls, md5sum, mkdir, mktemp, more, mount, mv, netstat, nslookup, ping,\n" +
			"\tps, pwd, rm, rmdir, route, sed, sh, sleep, sort, stty, sync, tail,\n" +
			"\ttar, tee, telnet, test, top, touch, tr, true, uname, uniq, uptime,\n" +
			"\twc, wget, which, whoami, xargs, yes, zcat\n", 0
	}

	applet := args[0]
	if applet == "--list" {
		return strings.Join(busyboxApplets, "\n") + "\n", 0
	}

	for _, a := range busyboxApplets {
		if a == applet {
			if fn, ok := builtins[a]; ok {
				return fn(s, a, args[1:], stdin)
			}
			return "", 0
		}
	}
	return fmt.Sprintf("%s: applet not found\n", applet), 127
}

var busyboxApplets = []string{
	"arch", "ash", "awk", "base64", "basename", "cat", "chgrp", "chmod",
	"chown", "cp", "cut", "date", "dd", "df", "dmesg", "echo", "egrep", "env",
	"false", "fgrep", "find", "grep", "gunzip", "gzip", "head", "hostname",
	"id", "ifconfig", "kill", "killall", "ln", "ls", "md5sum", "mkdir",
	"mktemp", "more", "mount", "mv", "netstat", "nslookup", "ping", "ps",
	"pwd", "rm", "rmdir", "route", "sed", "sh", "sleep", "sort", "stty",
	"sync", "tail", "tar", "tee", "telnet", "test", "top", "touch", "tr",
	"true", "uname", "uniq", "uptime", "wc", "wget", "which", "whoami",
	"xargs", "yes", "zcat",
}
