// Package personality derives a node's fake machine identity from a single seed.
//
// The problem this solves: stock honeypots ship identical fake systems. Every
// Cowrie install reports the same /proc/cpuinfo, the same hostname pattern, the
// same package list. Scanners fingerprint that in one request, tag the host, and
// the better botnets disconnect immediately -- which poisons the corpus with
// truncated sessions that cluster into their own meaningless group.
//
// Every value here is derived deterministically from the seed, so a node keeps a
// stable identity across restarts without persisting any state, while no two
// nodes in the fleet look alike.
package personality

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"time"
)

// Personality is a complete fake machine identity. Protocol handlers read from
// it rather than from the real host, so nothing about the actual VPS leaks into
// a session transcript.
type Personality struct {
	Seed string

	// TokenSecret keys the canary tokens planted in decoy files. Assigned
	// after derivation from the node's private credential secret, never
	// derived from Seed.
	//
	// Seed is a provisioning input and is routinely set to the node ID, which
	// is public the moment the sensor answers a connection. Tokens derived
	// from it could be precomputed for the whole fleet, and an attacker who
	// did that could both recognise a planted file on sight and burn the
	// tripwire by requesting tokens they were never given.
	//
	// Excluded from serialisation and from LogValue so it cannot reach a log
	// line or the --show-ident output.
	TokenSecret string `json:"-"`

	Hostname   string
	Distro     Distro
	KernelRel  string
	Arch       string
	CPUModel   string
	CPUCores   int
	CPUMHz     float64
	MemTotalKB int
	SwapKB     int
	MACAddr    string
	InternalIP string
	BootTime   time.Time

	SSHBanner  string
	SSHVersion string

	Users    []User
	Packages []string

	// Per-session timing behaviour. Sampled once per node so that a scanner
	// correlating two probes against the same host sees consistent latency.
	AuthFailBaseMS   int
	AuthFailJitterMS int
	EchoBaseMS       int
	EchoJitterMS     int

	// kernel carries the build string and ship date behind KernelRel, so that
	// /proc/version, the Debian MOTD and the uptime clamp all agree.
	kernel kernel

	// cpu carries the vendor, family and feature flags behind CPUModel, so
	// /proc/cpuinfo cannot describe an AMD part as an Intel one.
	cpu cpuModel
}

// kernelBuild is the build identification uname -v reports, e.g.
// "#1 SMP Debian 5.10.209-2 (2024-01-31)".
func (p *Personality) kernelBuild() string { return p.kernel.Build }

// Distro carries the identity strings that `uname`, /etc/os-release and the
// login banner all have to agree on. Disagreement between them is itself a
// fingerprint.
type Distro struct {
	ID         string
	Name       string
	Version    string
	VersionID  string
	Codename   string
	PrettyName string
}

// User is an account visible in /etc/passwd and in `who`/`last` output.
type User struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
	Gecos string
}

var distros = []Distro{
	{ID: "ubuntu", Name: "Ubuntu", Version: "22.04.4 LTS (Jammy Jellyfish)", VersionID: "22.04", Codename: "jammy", PrettyName: "Ubuntu 22.04.4 LTS"},
	{ID: "ubuntu", Name: "Ubuntu", Version: "20.04.6 LTS (Focal Fossa)", VersionID: "20.04", Codename: "focal", PrettyName: "Ubuntu 20.04.6 LTS"},
	{ID: "debian", Name: "Debian GNU/Linux", Version: "11 (bullseye)", VersionID: "11", Codename: "bullseye", PrettyName: "Debian GNU/Linux 11 (bullseye)"},
	{ID: "debian", Name: "Debian GNU/Linux", Version: "12 (bookworm)", VersionID: "12", Codename: "bookworm", PrettyName: "Debian GNU/Linux 12 (bookworm)"},
	{ID: "centos", Name: "CentOS Linux", Version: "7 (Core)", VersionID: "7", Codename: "Core", PrettyName: "CentOS Linux 7 (Core)"},
}

// kernel is one package-manager kernel build, with the date it shipped.
//
// The date is what keeps uptime honest. Uptime is drawn from a wide range so
// the fleet does not look freshly booted, but a box cannot have been up longer
// than its kernel has existed -- and `uname -r` next to `uptime` is two
// commands anyone runs in the first minute of a session. Derive clamps the boot
// time to this date.
type kernel struct {
	Release  string
	Build    string
	Released time.Time
}

func released(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// kernelsByDistro keeps uname output plausible for the chosen distribution.
// A Debian 12 box reporting a CentOS kernel string is an instant tell.
var kernelsByDistro = map[string][]kernel{
	"ubuntu": {
		{"5.15.0-91-generic", "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023", released(2023, time.December, 6)},
		{"5.15.0-105-generic", "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024", released(2024, time.April, 19)},
		{"5.4.0-174-generic", "#193-Ubuntu SMP Thu Feb 22 15:34:22 UTC 2024", released(2024, time.March, 4)},
		{"6.5.0-27-generic", "#28~22.04.1-Ubuntu SMP Fri Mar 22 15:07:59 UTC 2024", released(2024, time.April, 10)},
	},
	"debian": {
		{"5.10.0-28-amd64", "#1 SMP Debian 5.10.209-2 (2024-01-31)", released(2024, time.February, 5)},
		{"5.10.0-30-amd64", "#1 SMP Debian 5.10.218-1 (2024-06-01)", released(2024, time.June, 5)},
		{"6.1.0-18-amd64", "#1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)", released(2024, time.February, 8)},
	},
	"centos": {
		{"3.10.0-1160.108.1.el7.x86_64", "#1 SMP Thu Jan 25 16:17:31 UTC 2024", released(2024, time.January, 30)},
		{"3.10.0-1160.114.2.el7.x86_64", "#1 SMP Wed Mar 20 15:54:52 UTC 2024", released(2024, time.March, 26)},
	},
}

// sshBanners is weighted by observed real-world prevalence rather than being a
// uniform pick. A fleet where every OpenSSH version is equally likely is itself
// anomalous against the actual internet population.
var sshBanners = []struct {
	banner string
	weight int
}{
	{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", 22},
	{"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", 18},
	{"SSH-2.0-OpenSSH_7.4", 14},
	{"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3", 12},
	{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", 11},
	{"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2", 8},
	{"SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8", 5},
	{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4", 5},
	{"SSH-2.0-OpenSSH_8.0", 5},
}

// cpuModel carries everything /proc/cpuinfo has to keep consistent with the
// model name.
//
// vendor, family and model used to be hardcoded to Intel's values for every
// entry, so the AMD parts advertised "AMD EPYC 7B12" under vendor_id
// GenuineIntel with an Intel family and stepping. `cat /proc/cpuinfo` shows all
// of it in one screen.
type cpuModel struct {
	model  string
	mhz    float64
	vendor string
	family int
	num    int
	cache  string
	flags  string
}

const (
	intelFlags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single fsgsbase bmi1 avx2 smep bmi2 erms invpcid xsaveopt arat"

	// AMD parts expose a different feature set: no Intel-specific entries such
	// as tsc_known_freq or invpcid_single, plus the AMD-only extensions.
	amdFlags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm rep_good nopl cpuid extd_apicid tsc_known_freq pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy svm cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext perfctr_core ssbd ibpb vmmcall fsgsbase bmi1 avx2 smep bmi2 rdseed adx smap clflushopt sha_ni xsaveopt xsavec xgetbv1 clzero xsaveerptr arat npt nrip_save umip rdpid"
)

var cpuModels = []cpuModel{
	{"Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz", 2400.000, "GenuineIntel", 6, 79, "35840 KB", intelFlags},
	{"Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz", 2300.000, "GenuineIntel", 6, 63, "30720 KB", intelFlags},
	{"Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz", 3000.000, "GenuineIntel", 6, 85, "36608 KB", intelFlags},
	{"Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz", 2500.000, "GenuineIntel", 6, 85, "36608 KB", intelFlags},
	{"AMD EPYC 7401P 24-Core Processor", 2000.000, "AuthenticAMD", 23, 1, "512 KB", amdFlags},
	{"AMD EPYC 7B12", 2250.000, "AuthenticAMD", 23, 49, "512 KB", amdFlags},
	{"Intel(R) Xeon(R) CPU E3-1245 v5 @ 3.50GHz", 3500.000, "GenuineIntel", 6, 94, "8192 KB", intelFlags},
}

// hostnamePatterns reflect how real VPS instances are actually named: provider
// defaults, role-based names, and datacentre-coded names.
var hostnamePatterns = []func(r *rand.Rand) string{
	func(r *rand.Rand) string { return fmt.Sprintf("vps-%06d", r.Intn(1000000)) },
	func(r *rand.Rand) string { return fmt.Sprintf("srv%02d", r.Intn(40)+1) },
	func(r *rand.Rand) string {
		roles := []string{"web", "db", "mail", "app", "node", "cache", "proxy", "build"}
		return fmt.Sprintf("%s-%02d", roles[r.Intn(len(roles))], r.Intn(12)+1)
	},
	func(r *rand.Rand) string {
		dc := []string{"nyc", "sfo", "ams", "fra", "sgp", "lon", "tor"}
		return fmt.Sprintf("%s%d-prod-%02d", dc[r.Intn(len(dc))], r.Intn(3)+1, r.Intn(20)+1)
	},
	func(r *rand.Rand) string { return fmt.Sprintf("localhost-%d", r.Intn(100)) },
	func(r *rand.Rand) string {
		return fmt.Sprintf("ip-172-31-%d-%d", r.Intn(256), r.Intn(256))
	},
}

var basePackages = []string{
	"apt", "base-files", "bash", "bsdutils", "coreutils", "cron", "curl",
	"dash", "diffutils", "dpkg", "e2fsprogs", "findutils", "grep", "gzip",
	"hostname", "init-system-helpers", "iproute2", "iputils-ping", "less",
	"login", "logrotate", "mount", "nano", "ncurses-base", "netbase",
	"openssh-client", "openssh-server", "passwd", "perl-base", "procps",
	"python3", "rsyslog", "sed", "sensible-utils", "sudo", "sysvinit-utils",
	"tar", "ubuntu-keyring", "util-linux", "vim-tiny", "wget", "zlib1g",
}

// optionalPackages give each node a plausible reason to exist. A box with
// nginx and certbot reads differently from one with mysql-server, and that
// variation is what stops the fleet looking cloned.
var optionalPackages = []string{
	"nginx", "apache2", "mysql-server", "mariadb-server", "postgresql",
	"redis-server", "php-fpm", "php-cli", "nodejs", "npm", "git", "docker.io",
	"certbot", "fail2ban", "ufw", "htop", "tmux", "screen", "unzip", "zip",
	"build-essential", "supervisor", "memcached", "postfix", "dovecot-core",
	"samba", "nfs-common", "rsync", "sqlite3", "jq",
}

var userNames = []string{
	"admin", "deploy", "ubuntu", "debian", "webadmin", "sysop", "backup",
	"jenkins", "gitlab", "ansible", "monitor", "svc-app", "dev", "operator",
}

// Derive builds a Personality from a seed string. Same seed always yields the
// same machine, so a node need not persist anything to stay consistent.
func Derive(seed string) *Personality {
	sum := sha256.Sum256([]byte("honeynet/personality/v1:" + seed))
	r := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(sum[:8])))) //nolint:gosec // deterministic identity derivation, not security

	distro := distros[r.Intn(len(distros))]
	kernels := kernelsByDistro[distro.ID]
	cpu := cpuModels[r.Intn(len(cpuModels))]

	// Cores and memory correlate on real VPS plans; independent draws produce
	// implausible shapes like 1 core with 64GB.
	coreChoices := []int{1, 2, 2, 4, 4, 8, 16}
	cores := coreChoices[r.Intn(len(coreChoices))]
	memGB := cores * []int{1, 2, 2, 4}[r.Intn(4)]

	kern := kernels[r.Intn(len(kernels))]

	p := &Personality{
		Seed:       seed,
		Hostname:   hostnamePatterns[r.Intn(len(hostnamePatterns))](r),
		Distro:     distro,
		KernelRel:  kern.Release,
		kernel:     kern,
		Arch:       "x86_64",
		CPUModel:   cpu.model,
		cpu:        cpu,
		CPUCores:   cores,
		CPUMHz:     cpu.mhz + float64(r.Intn(200))-100,

		// Never an exact power of two. Real firmware and the kernel reserve a
		// slice before MemTotal is reported, so a machine advertising exactly
		// 4194304 kB has never existed; the reserved fraction varies by host,
		// which is why it is drawn rather than fixed.
		MemTotalKB: memGB*1024*1024 - (16*1024 + r.Intn(48*1024)),
		SwapKB:     []int{0, 524288, 1048576, 2097152}[r.Intn(4)],
		MACAddr:    deriveMAC(r),
		InternalIP: fmt.Sprintf("10.%d.%d.%d", r.Intn(256), r.Intn(256), r.Intn(254)+1),

		// Uptime between roughly two weeks and two years. A fleet of hosts all
		// booted an hour ago is the loudest possible tell.
		BootTime: time.Now().Add(-time.Duration(r.Intn(700-14)+14) * 24 * time.Hour).
			Add(-time.Duration(r.Intn(86400)) * time.Second),

		AuthFailBaseMS:   900 + r.Intn(1400),
		AuthFailJitterMS: 120 + r.Intn(400),
		EchoBaseMS:       2 + r.Intn(12),
		EchoJitterMS:     1 + r.Intn(9),
	}

	// A box cannot have been running longer than its kernel has existed. The
	// unclamped draw reached back two years, which for a kernel released a few
	// months ago is an impossibility that `uname -r` and `uptime` expose
	// together.
	if p.BootTime.Before(kern.Released) {
		span := time.Since(kern.Released)
		if span <= 0 {
			span = time.Hour
		}
		p.BootTime = kern.Released.Add(time.Duration(r.Int63n(int64(span))))
	}

	p.SSHBanner = pickBanner(r)
	p.SSHVersion = strings.TrimPrefix(p.SSHBanner, "SSH-2.0-")
	p.Users = deriveUsers(r, distro)
	p.Packages = derivePackages(r)

	return p
}

func deriveMAC(r *rand.Rand) string {
	// Locally-administered unicast prefixes used by common hypervisors, so the
	// OUI does not read as a physical NIC on a machine claiming to be a VM.
	ouis := [][3]byte{
		{0x52, 0x54, 0x00}, // QEMU/KVM
		{0x00, 0x16, 0x3e}, // Xen
		{0x00, 0x50, 0x56}, // VMware
		{0x06, 0x00, 0x00}, // AWS-style locally administered
	}
	o := ouis[r.Intn(len(ouis))]
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		o[0], o[1], o[2], r.Intn(256), r.Intn(256), r.Intn(256))
}

func pickBanner(r *rand.Rand) string {
	total := 0
	for _, b := range sshBanners {
		total += b.weight
	}
	n := r.Intn(total)
	for _, b := range sshBanners {
		n -= b.weight
		if n < 0 {
			return b.banner
		}
	}
	return sshBanners[0].banner
}

func deriveUsers(r *rand.Rand, d Distro) []User {
	users := []User{
		{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash", Gecos: "root"},
	}

	// The distro's own default account, which a real image would have.
	switch d.ID {
	case "ubuntu":
		users = append(users, User{Name: "ubuntu", UID: 1000, GID: 1000, Home: "/home/ubuntu", Shell: "/bin/bash", Gecos: "Ubuntu"})
	case "debian":
		users = append(users, User{Name: "debian", UID: 1000, GID: 1000, Home: "/home/debian", Shell: "/bin/bash", Gecos: ""})
	case "centos":
		users = append(users, User{Name: "centos", UID: 1000, GID: 1000, Home: "/home/centos", Shell: "/bin/bash", Gecos: "Cloud User"})
	}

	next := 1001
	extra := r.Intn(3) + 1
	picked := map[string]bool{}
	for i := 0; i < extra; i++ {
		name := userNames[r.Intn(len(userNames))]
		if picked[name] {
			continue
		}
		picked[name] = true
		users = append(users, User{
			Name: name, UID: next, GID: next,
			Home: "/home/" + name, Shell: "/bin/bash",
		})
		next++
	}
	return users
}

func derivePackages(r *rand.Rand) []string {
	pkgs := append([]string{}, basePackages...)

	shuffled := append([]string{}, optionalPackages...)
	r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	n := r.Intn(10) + 5
	pkgs = append(pkgs, shuffled[:n]...)
	return pkgs
}

// LogValue renders the personality for structured logging with the token
// secret withheld. Without this, logging the struct at debug level would put
// the value that keys every canary token into the log stream.
func (p *Personality) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("hostname", p.Hostname),
		slog.String("distro", p.Distro.PrettyName),
		slog.String("kernel", p.KernelRel),
		slog.String("arch", p.Arch),
		slog.String("ssh_banner", p.SSHBanner),
	)
}

// Uptime returns the elapsed time since the derived boot time.
func (p *Personality) Uptime() time.Duration { return time.Since(p.BootTime) }

// AccountNames lists the node's login accounts.
//
// This is the single source of the roster: the credential policy derives one
// password per name here, and Passwd() renders the same set into /etc/passwd.
// Sourcing both from this method is what stops a sensor from authenticating an
// account that the attacker cannot then find on the system.
func (p *Personality) AccountNames() []string {
	out := make([]string, 0, len(p.Users))
	for _, u := range p.Users {
		out = append(out, u.Name)
	}
	return out
}

// MachineID renders a plausible /etc/machine-id: 32 lowercase hex characters.
func (p *Personality) MachineID() string {
	sum := sha256.Sum256([]byte("machine-id:" + p.Seed))
	return hex.EncodeToString(sum[:16])
}

// ProcCPUInfo renders /proc/cpuinfo for every derived core.
func (p *Personality) ProcCPUInfo() string {
	var b strings.Builder
	for i := 0; i < p.CPUCores; i++ {
		fmt.Fprintf(&b, "processor\t: %d\n", i)
		fmt.Fprintf(&b, "vendor_id\t: %s\n", p.cpu.vendor)
		fmt.Fprintf(&b, "cpu family\t: %d\n", p.cpu.family)
		fmt.Fprintf(&b, "model\t\t: %d\n", p.cpu.num)
		fmt.Fprintf(&b, "model name\t: %s\n", p.CPUModel)
		b.WriteString("stepping\t: 1\n")
		fmt.Fprintf(&b, "cpu MHz\t\t: %.3f\n", p.CPUMHz)
		fmt.Fprintf(&b, "cache size\t: %s\n", p.cpu.cache)
		fmt.Fprintf(&b, "physical id\t: %d\n", 0)
		fmt.Fprintf(&b, "siblings\t: %d\n", p.CPUCores)
		fmt.Fprintf(&b, "core id\t\t: %d\n", i)
		fmt.Fprintf(&b, "cpu cores\t: %d\n", p.CPUCores)
		b.WriteString("fpu\t\t: yes\n")
		fmt.Fprintf(&b, "flags\t\t: %s\n", p.cpu.flags)
		fmt.Fprintf(&b, "bogomips\t: %.2f\n", p.CPUMHz*2)
		b.WriteString("clflush size\t: 64\n")
		b.WriteString("cache_alignment\t: 64\n")
		b.WriteString("address sizes\t: 46 bits physical, 48 bits virtual\n")
		b.WriteString("power management:\n")
		b.WriteString("\n")
	}
	return b.String()
}

// ProcMemInfo renders /proc/meminfo with internally consistent totals. Free
// memory is derived from the seed rather than randomised per call, so two reads
// in one session do not contradict each other.
func (p *Personality) ProcMemInfo() string {
	free := p.MemTotalKB / 8
	buffers := p.MemTotalKB / 40
	cached := p.MemTotalKB / 4
	available := free + cached + buffers

	var b strings.Builder
	fmt.Fprintf(&b, "MemTotal:       %8d kB\n", p.MemTotalKB)
	fmt.Fprintf(&b, "MemFree:        %8d kB\n", free)
	fmt.Fprintf(&b, "MemAvailable:   %8d kB\n", available)
	fmt.Fprintf(&b, "Buffers:        %8d kB\n", buffers)
	fmt.Fprintf(&b, "Cached:         %8d kB\n", cached)
	fmt.Fprintf(&b, "SwapCached:     %8d kB\n", 0)
	fmt.Fprintf(&b, "Active:         %8d kB\n", p.MemTotalKB/3)
	fmt.Fprintf(&b, "Inactive:       %8d kB\n", p.MemTotalKB/5)
	fmt.Fprintf(&b, "SwapTotal:      %8d kB\n", p.SwapKB)
	fmt.Fprintf(&b, "SwapFree:       %8d kB\n", p.SwapKB)
	fmt.Fprintf(&b, "Dirty:          %8d kB\n", 128)
	fmt.Fprintf(&b, "Writeback:      %8d kB\n", 0)
	fmt.Fprintf(&b, "Slab:           %8d kB\n", p.MemTotalKB/50)
	return b.String()
}

// ProcVersion renders /proc/version, agreeing with the derived kernel release.
func (p *Personality) ProcVersion() string {
	builder := "buildd@lcy02-amd64-042"
	gcc := "11.4.0"
	if p.Distro.ID == "centos" {
		builder = "mockbuild@kbuilder.bsys.centos.org"
		gcc = "4.8.5 20150623 (Red Hat 4.8.5-44)"
	}
	// The trailer is the kernel's build identification, not the boot time.
	// /proc/version reports when the kernel was compiled; deriving it from
	// boot time made every node claim a kernel built the instant it started.
	return fmt.Sprintf("Linux version %s (%s) (gcc (GCC) %s) %s\n",
		p.KernelRel, builder, gcc, p.kernel.Build)
}

// ProcUptime renders /proc/uptime: seconds since boot, then idle seconds.
func (p *Personality) ProcUptime() string {
	up := p.Uptime().Seconds()
	return fmt.Sprintf("%.2f %.2f\n", up, up*float64(p.CPUCores)*0.94)
}

// OSRelease renders /etc/os-release.
func (p *Personality) OSRelease() string {
	d := p.Distro
	var b strings.Builder
	fmt.Fprintf(&b, "PRETTY_NAME=\"%s\"\n", d.PrettyName)
	fmt.Fprintf(&b, "NAME=\"%s\"\n", d.Name)
	fmt.Fprintf(&b, "VERSION_ID=\"%s\"\n", d.VersionID)
	fmt.Fprintf(&b, "VERSION=\"%s\"\n", d.Version)
	fmt.Fprintf(&b, "ID=%s\n", d.ID)

	// Each distribution's own trailer. The previous version emitted Ubuntu's
	// for all three, so a Debian or CentOS node advertised UBUNTU_CODENAME in
	// its own /etc/os-release -- a contradiction anyone reads the moment the
	// shell opens, and one that costs nothing to get right.
	switch d.ID {
	case "ubuntu":
		b.WriteString("ID_LIKE=debian\n")
		b.WriteString("HOME_URL=\"https://www.ubuntu.com/\"\n")
		b.WriteString("SUPPORT_URL=\"https://help.ubuntu.com/\"\n")
		b.WriteString("BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n")
		b.WriteString("PRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\n")
		fmt.Fprintf(&b, "UBUNTU_CODENAME=%s\n", d.Codename)
	case "debian":
		b.WriteString("HOME_URL=\"https://www.debian.org/\"\n")
		b.WriteString("SUPPORT_URL=\"https://www.debian.org/support\"\n")
		b.WriteString("BUG_REPORT_URL=\"https://bugs.debian.org/\"\n")
	case "centos":
		b.WriteString("ID_LIKE=\"rhel fedora\"\n")
		b.WriteString("ANSI_COLOR=\"0;31\"\n")
		fmt.Fprintf(&b, "CPE_NAME=\"cpe:/o:centos:centos:%s\"\n", d.VersionID)
		b.WriteString("HOME_URL=\"https://www.centos.org/\"\n")
		b.WriteString("BUG_REPORT_URL=\"https://bugs.centos.org/\"\n")
		fmt.Fprintf(&b, "CENTOS_MANTISBT_PROJECT=\"CentOS-%s\"\n", d.VersionID)
		fmt.Fprintf(&b, "REDHAT_SUPPORT_PRODUCT_VERSION=\"%s\"\n", d.VersionID)
	}
	return b.String()
}

// Passwd renders /etc/passwd: the standard system accounts every real box has,
// followed by the derived human accounts.
func (p *Personality) Passwd() string {
	var b strings.Builder
	system := []string{
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin",
		"sys:x:3:3:sys:/dev:/usr/sbin/nologin",
		"sync:x:4:65534:sync:/bin:/bin/sync",
		"games:x:5:60:games:/usr/games:/usr/sbin/nologin",
		"man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
		"lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
		"mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
		"news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
		"sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
	}
	for _, u := range p.Users {
		if u.UID == 0 {
			fmt.Fprintf(&b, "%s:x:%d:%d:%s:%s:%s\n", u.Name, u.UID, u.GID, u.Gecos, u.Home, u.Shell)
		}
	}
	for _, line := range system {
		b.WriteString(line + "\n")
	}
	for _, u := range p.Users {
		if u.UID != 0 {
			fmt.Fprintf(&b, "%s:x:%d:%d:%s:%s:%s\n", u.Name, u.UID, u.GID, u.Gecos, u.Home, u.Shell)
		}
	}
	return b.String()
}

// MOTD renders the login banner. Distro-appropriate, with an uptime-consistent
// "last login" line supplied separately by the shell.
func (p *Personality) MOTD() string {
	// Each distribution has its own login banner, and they look nothing alike.
	// This used to serve Canonical's for Debian as well: a Debian box pointing
	// the operator at help.ubuntu.com and landscape.canonical.com, which is
	// not a subtle inconsistency but the wrong operating system's branding on
	// the first screen after login.
	switch p.Distro.ID {
	case "centos":
		// CentOS 7 ships no MOTD by default.
		return ""

	case "debian":
		var b strings.Builder
		fmt.Fprintf(&b, "Linux %s %s %s %s\r\n\r\n", p.Hostname, p.KernelRel, p.kernelBuild(), p.Arch)
		b.WriteString("The programs included with the Debian GNU/Linux system are free software;\r\n")
		b.WriteString("the exact distribution terms for each program are described in the\r\n")
		b.WriteString("individual files in /usr/share/doc/*/copyright.\r\n\r\n")
		b.WriteString("Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\r\n")
		b.WriteString("permitted by applicable law.\r\n")
		return b.String()

	default:
		var b strings.Builder
		fmt.Fprintf(&b, "Welcome to %s (GNU/Linux %s %s)\r\n\r\n", p.Distro.PrettyName, p.KernelRel, p.Arch)
		b.WriteString(" * Documentation:  https://help.ubuntu.com\r\n")
		b.WriteString(" * Management:     https://landscape.canonical.com\r\n")
		b.WriteString(" * Support:        https://ubuntu.com/advantage\r\n\r\n")
		fmt.Fprintf(&b, "  System information as of %s\r\n\r\n", time.Now().UTC().Format("Mon Jan  2 15:04:05 UTC 2006"))
		fmt.Fprintf(&b, "  System load:  %.2f              Processes:             %d\r\n", 0.08, 120+len(p.Packages))
		fmt.Fprintf(&b, "  Usage of /:   %.1f%% of %.2fGB   Users logged in:       0\r\n", 34.2, 38.71)
		fmt.Fprintf(&b, "  Memory usage: %d%%                IPv4 address for eth0: %s\r\n", 12, p.InternalIP)
		fmt.Fprintf(&b, "  Swap usage:   %d%%\r\n\r\n", 0)
		b.WriteString("0 updates can be applied immediately.\r\n\r\n")
		return b.String()
	}
}
