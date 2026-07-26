package personality

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Every assertion here is a tell that shipped at least once. They are checked
// across a wide seed sweep rather than one personality, because the derivation
// is random and a contradiction that appears in one draw out of fifty is still
// a contradiction on some node in the fleet.
func sweep(t *testing.T, n int, fn func(t *testing.T, p *Personality)) {
	t.Helper()
	for i := 0; i < n; i++ {
		p := Derive(fmt.Sprintf("sweep-seed-%d", i))
		fn(t, p)
	}
}

// The loudest of the original defects: Debian nodes served Canonical's MOTD,
// pointing the operator at help.ubuntu.com on the first screen after login.
func TestMOTDDoesNotAdvertiseTheWrongDistribution(t *testing.T) {
	sweep(t, 400, func(t *testing.T, p *Personality) {
		motd := p.MOTD()
		if p.Distro.ID == "ubuntu" {
			return
		}
		for _, marker := range []string{"ubuntu.com", "canonical", "Ubuntu"} {
			if strings.Contains(strings.ToLower(motd), strings.ToLower(marker)) {
				t.Errorf("%s node MOTD contains %q:\n%s", p.Distro.ID, marker, motd)
			}
		}
	})
}

// /etc/os-release carried UBUNTU_CODENAME on Debian and CentOS.
func TestOSReleaseIsDistributionSpecific(t *testing.T) {
	sweep(t, 400, func(t *testing.T, p *Personality) {
		rel := p.OSRelease()

		if p.Distro.ID != "ubuntu" && strings.Contains(rel, "UBUNTU_CODENAME") {
			t.Errorf("%s node advertises UBUNTU_CODENAME:\n%s", p.Distro.ID, rel)
		}
		if !strings.Contains(rel, "ID="+p.Distro.ID) {
			t.Errorf("os-release does not declare ID=%s:\n%s", p.Distro.ID, rel)
		}

		// The home URL has to belong to the distribution claiming it.
		wantHost := map[string]string{
			"ubuntu": "ubuntu.com",
			"debian": "debian.org",
			"centos": "centos.org",
		}[p.Distro.ID]
		if !strings.Contains(rel, wantHost) {
			t.Errorf("%s node os-release does not reference %s:\n%s", p.Distro.ID, wantHost, rel)
		}
	})
}

// /proc/cpuinfo described AMD parts as GenuineIntel with an Intel family.
func TestCPUInfoVendorMatchesModel(t *testing.T) {
	sweep(t, 400, func(t *testing.T, p *Personality) {
		info := p.ProcCPUInfo()

		switch {
		case strings.Contains(p.CPUModel, "AMD"):
			if !strings.Contains(info, "AuthenticAMD") {
				t.Errorf("AMD model %q reports the wrong vendor_id", p.CPUModel)
			}
			if strings.Contains(info, "GenuineIntel") {
				t.Errorf("AMD model %q reports GenuineIntel", p.CPUModel)
			}
		case strings.Contains(p.CPUModel, "Intel"):
			if !strings.Contains(info, "GenuineIntel") {
				t.Errorf("Intel model %q reports the wrong vendor_id", p.CPUModel)
			}
			if strings.Contains(info, "AuthenticAMD") {
				t.Errorf("Intel model %q reports AuthenticAMD", p.CPUModel)
			}
		}

		// The flag list has to match the vendor too; svm is AMD's
		// virtualisation flag and has never appeared on an Intel part.
		if strings.Contains(info, "GenuineIntel") && strings.Contains(info, " svm ") {
			t.Errorf("Intel model %q advertises the AMD svm flag", p.CPUModel)
		}
	})
}

// `uname -r` and `uptime` are two commands anyone runs in the first minute. A
// box cannot have been up longer than its kernel has existed.
func TestUptimeDoesNotPredateTheKernel(t *testing.T) {
	sweep(t, 400, func(t *testing.T, p *Personality) {
		if p.BootTime.Before(p.kernel.Released) {
			t.Errorf("kernel %s shipped %s but the node claims to have booted %s",
				p.KernelRel,
				p.kernel.Released.Format(time.DateOnly),
				p.BootTime.Format(time.DateOnly))
		}
		if p.Uptime() < 0 {
			t.Errorf("negative uptime for kernel %s", p.KernelRel)
		}
	})
}

// Firmware and the kernel reserve memory before MemTotal is reported, so an
// exact power of two has never been observed on real hardware.
func TestMemTotalIsNotAnExactPowerOfTwo(t *testing.T) {
	sweep(t, 400, func(t *testing.T, p *Personality) {
		kb := p.MemTotalKB
		if kb > 0 && kb&(kb-1) == 0 {
			t.Errorf("MemTotal is exactly %d kB, a power of two", kb)
		}
		if !strings.Contains(p.ProcMemInfo(), "MemTotal:") {
			t.Error("meminfo is missing MemTotal")
		}
	})
}

// /proc/version reports when the kernel was built, not when the box booted.
func TestProcVersionCarriesTheBuildNotTheBootTime(t *testing.T) {
	sweep(t, 200, func(t *testing.T, p *Personality) {
		v := p.ProcVersion()
		if !strings.Contains(v, p.KernelRel) {
			t.Errorf("/proc/version does not name the kernel release:\n%s", v)
		}
		if !strings.Contains(v, p.kernel.Build) {
			t.Errorf("/proc/version does not carry the build identification:\n%s", v)
		}
	})
}

// The kernel string has to belong to the distribution serving it.
func TestKernelMatchesDistribution(t *testing.T) {
	sweep(t, 400, func(t *testing.T, p *Personality) {
		switch p.Distro.ID {
		case "centos":
			if !strings.Contains(p.KernelRel, ".el7.") {
				t.Errorf("CentOS node runs kernel %q", p.KernelRel)
			}
		case "debian":
			if !strings.HasSuffix(p.KernelRel, "-amd64") {
				t.Errorf("Debian node runs kernel %q", p.KernelRel)
			}
		case "ubuntu":
			if !strings.HasSuffix(p.KernelRel, "-generic") {
				t.Errorf("Ubuntu node runs kernel %q", p.KernelRel)
			}
		}
	})
}

// The SSH banner must name a build the claimed distribution actually ships.
//
// This shipped broken: the banner was drawn independently of the distribution,
// so an Ubuntu 22.04 node could announce a CentOS-era OpenSSH 7.4. Found by
// pointing a real OpenSSH client at a running sensor, not by reading the code.
func TestSSHBannerMatchesTheDistribution(t *testing.T) {
	sweep(t, 400, func(t *testing.T, p *Personality) {
		banner := p.SSHBanner

		switch p.Distro.ID {
		case "ubuntu":
			if !strings.Contains(banner, "Ubuntu") {
				t.Errorf("%s node advertises %q", p.Distro.PrettyName, banner)
			}
		case "debian":
			if !strings.Contains(banner, "Debian") {
				t.Errorf("%s node advertises %q", p.Distro.PrettyName, banner)
			}
		}

		// The version has to be one the handshake can serve honestly. Anything
		// below 8.x needs key exchanges this transport cannot offer, so the
		// node would advertise an algorithm set from the wrong decade.
		if !strings.Contains(banner, "OpenSSH_8.") && !strings.Contains(banner, "OpenSSH_9.") {
			t.Errorf("banner %q names a release the algorithm tables cannot serve", banner)
		}
	})
}

// The credential policy derives one password per account from this roster, and
// the shell renders the same roster into /etc/passwd. If they diverged, an
// account could authenticate and then not exist on the system.
func TestAccountRosterMatchesPasswd(t *testing.T) {
	sweep(t, 200, func(t *testing.T, p *Personality) {
		passwd := p.Passwd()
		for _, name := range p.AccountNames() {
			if !strings.Contains(passwd, name+":x:") {
				t.Errorf("account %q is on the roster but absent from /etc/passwd", name)
			}
		}
	})
}

// The secret that keys canary tokens must not reach a log line.
func TestLogValueOmitsTheTokenSecret(t *testing.T) {
	p := Derive("log-redaction")
	p.TokenSecret = "super-secret-token-key"

	rendered := fmt.Sprintf("%v", p.LogValue())
	if strings.Contains(rendered, p.TokenSecret) {
		t.Errorf("LogValue leaked the token secret: %s", rendered)
	}
}
