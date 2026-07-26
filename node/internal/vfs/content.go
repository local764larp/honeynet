package vfs

// Static filesystem content. These are the files a scanner is most likely to
// read, so they are reproduced faithfully rather than stubbed -- a truncated
// or subtly wrong /etc/crontab is a cheap tell.

// elfStub is the first bytes of a 64-bit ELF header followed by padding. Enough
// that `head -c4 /bin/ls` and `file`-style magic checks see something sane.
// Nothing in the node ever executes these bytes; the shell dispatches on
// command name.
const elfStub = "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
	"\x03\x00\x3e\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

const bashrc = `# ~/.bashrc: executed by bash(1) for non-login shells.

case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s checkwinsize

[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
fi

alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
`

const rootBashrc = `# ~/.bashrc: executed by bash(1) for non-login shells.

export PS1="\h:\w\$ "
umask 022

alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -l'
alias l='ls $LS_OPTIONS -lA'

alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
`

const profile = `# ~/.profile: executed by the command interpreter for login shells.

if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
	. "$HOME/.bashrc"
    fi
fi

if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
`

const bashLogout = `# ~/.bash_logout: executed by bash(1) when login shell exits.

if [ "$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi
`

const etcCrontab = `# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
`

const sshdConfig = `Include /etc/ssh/sshd_config.d/*.conf

Port 22
#AddressFamily any
#ListenAddress 0.0.0.0

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

#SyslogFacility AUTH
#LogLevel INFO

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes
PasswordAuthentication yes
#PermitEmptyPasswords no

ChallengeResponseAuthentication no
UsePAM yes

X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server
`

const procFilesystems = `nodev	sysfs
nodev	tmpfs
nodev	bdev
nodev	proc
nodev	cgroup
nodev	cgroup2
nodev	cpuset
nodev	devtmpfs
nodev	configfs
nodev	debugfs
nodev	tracefs
nodev	securityfs
nodev	sockfs
nodev	bpf
nodev	pipefs
nodev	ramfs
nodev	hugetlbfs
nodev	devpts
	ext3
	ext2
	ext4
	squashfs
	vfat
nodev	overlay
nodev	autofs
nodev	mqueue
`

const procMounts = `sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
udev /dev devtmpfs rw,nosuid,relatime,size=1980516k,nr_inodes=495129,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=403844k,mode=755 0 0
/dev/vda1 / ext4 rw,relatime,errors=remount-ro 0 0
securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0
`

// coreutils, usrBins and sbins populate /bin, /usr/bin and /sbin. The lists
// matter because `ls /bin` and `which <tool>` are standard reconnaissance, and
// a sparse /bin reads as a container or an emulator.
var coreutils = []string{
	"bash", "cat", "chgrp", "chmod", "chown", "cp", "dash", "date", "dd", "df",
	"dir", "dmesg", "dnsdomainname", "echo", "egrep", "false", "fgrep", "grep",
	"gunzip", "gzip", "hostname", "ip", "kill", "ln", "login", "ls", "lsblk",
	"mkdir", "mknod", "mktemp", "more", "mount", "mv", "nano", "netstat",
	"networkctl", "nisdomainname", "ping", "ps", "pwd", "rbash", "readlink",
	"rm", "rmdir", "run-parts", "sed", "sh", "sleep", "ss", "stty", "su",
	"sync", "tar", "tempfile", "touch", "true", "umount", "uname", "uncompress",
	"vdir", "wdctl", "which", "ypdomainname", "zcat", "busybox",
}

var usrBins = []string{
	"apt", "apt-get", "awk", "base64", "basename", "bunzip2", "bzip2", "cksum",
	"comm", "curl", "cut", "diff", "dirname", "du", "env", "expr", "file",
	"find", "free", "ftp", "gcc", "gdb", "git", "head", "hexdump", "hostid",
	"htop", "id", "install", "iostat", "killall", "last", "ldd", "less",
	"lscpu", "lsof", "make", "md5sum", "mesg", "nc", "netcat", "nl", "nohup",
	"nproc", "nslookup", "openssl", "passwd", "perl", "pgrep", "pkill", "pkg",
	"printf", "python3", "realpath", "renice", "rsync", "scp", "screen",
	"sftp", "sha1sum", "sha256sum", "sort", "ssh", "stat", "strace", "strings",
	"sudo", "tail", "tcpdump", "tee", "telnet", "tftp", "time", "timeout",
	"top", "tr", "traceroute", "tty", "uniq", "unzip", "uptime", "users",
	"vim", "w", "watch", "wc", "wget", "whereis", "who", "whoami", "xargs",
	"xxd", "yes", "zip",
}

var sbins = []string{
	"adduser", "arp", "blkid", "chroot", "cron", "dhclient", "e2fsck",
	"fdisk", "fsck", "getty", "groupadd", "halt", "ifconfig", "ifdown",
	"ifup", "init", "insmod", "iptables", "iptables-save", "ldconfig",
	"lsmod", "mkfs", "modprobe", "nologin", "poweroff", "reboot", "route",
	"rmmod", "runlevel", "service", "shutdown", "sshd", "swapon", "sysctl",
	"tune2fs", "useradd", "userdel", "usermod",
}
