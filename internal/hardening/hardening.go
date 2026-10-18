// Package hardening looks for signs that a container was started with
// isolation turned off (--privileged and friends), and reports the root
// filesystem and cgroup limits.
package hardening

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/genuinetools/amicontained/internal/container"
	"github.com/genuinetools/amicontained/internal/procfs"
)

// Report is what Assess found.
type Report struct {
	Privileged     Privileged `json:"privileged"`
	RootFSReadOnly bool       `json:"rootfs_read_only"`
	Cgroup         Cgroup     `json:"cgroup"`
}

// Privileged is the set of privileged-container indicators.
type Privileged struct {
	Indicators []Indicator `json:"indicators"`
	Present    int         `json:"present"`
	Verdict    string      `json:"verdict"`
}

// Indicator is one sign of reduced isolation.
type Indicator struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Detail  string `json:"detail,omitempty"`
}

// Cgroup describes our cgroup and its limits. Limits hold the raw kernel
// value, with "max" meaning unlimited; CPUMax is "<quota> <period>".
type Cgroup struct {
	Version   string `json:"version"`
	Path      string `json:"path,omitempty"`
	MemoryMax string `json:"memory_max,omitempty"`
	CPUMax    string `json:"cpu_max,omitempty"`
	PIDsMax   string `json:"pids_max,omitempty"`
}

// Inputs are the results of other checks that the indicators build on.
type Inputs struct {
	Bounding        []string
	SeccompDisabled bool
	LSMConfined     bool
	UserNamespace   bool
	// Sandbox is a detected sandbox such as gvisor or kata, whose kernel is
	// what these indicators describe.
	Sandbox string
}

// Assess inspects the running system.
func Assess(in Inputs) *Report {
	return assess(os.DirFS("/"), procfs.Mounts(), in)
}

func assess(fsys fs.FS, mounts []procfs.Mount, in Inputs) *Report {
	r := &Report{}
	if m, ok := procfs.MountFor(mounts, "/"); ok {
		r.RootFSReadOnly = m.ReadOnly()
	}
	r.Cgroup = cgroup(fsys, mounts, read(fsys, "proc/self/cgroup"))

	p := &r.Privileged
	add := func(name string, present bool, detail string) {
		p.Indicators = append(p.Indicators, Indicator{Name: name, Present: present, Detail: detail})
		if present {
			p.Present++
		}
	}

	devs := hostDevices(fsys)
	add("host devices in /dev", len(devs) > 0, summarise(devs, 8))

	for _, dir := range []string{"/sys", "/proc/sys"} {
		m, ok := procfs.MountFor(mounts, dir)
		add(dir+" mounted read-write", ok && !m.ReadOnly(), "")
	}

	unmasked := unmaskedPaths(fsys, mounts)
	add("masked paths exposed", len(unmasked) > 0, summarise(unmasked, 8))

	lastCap := -1
	if n, err := strconv.Atoi(read(fsys, "proc/sys/kernel/cap_last_cap")); err == nil {
		lastCap = n
	}
	full := lastCap >= 0 && len(in.Bounding) == lastCap+1
	add("all capabilities in bounding set", full, fmt.Sprintf("%d of %d", len(in.Bounding), lastCap+1))

	add("seccomp disabled", in.SeccompDisabled, "")
	add("no LSM confinement", !in.LSMConfined, "")

	switch {
	case p.Present == 0:
		p.Verdict = "none present"
	case p.Present >= 5:
		p.Verdict = "looks privileged"
	default:
		p.Verdict = "some present"
	}
	if p.Present > 0 && in.UserNamespace {
		p.Verdict += "; in a user namespace, so capabilities apply only within it"
	}
	if p.Present > 0 && in.Sandbox != "" {
		p.Verdict += "; inside a " + in.Sandbox + " sandbox, so these describe " + container.SandboxKernel(in.Sandbox) + ", not the host"
	}
	return r
}

func read(fsys fs.FS, name string) string {
	b, _ := fs.ReadFile(fsys, name)
	return strings.TrimSpace(string(b))
}

func summarise(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, " ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(items[:max], " "), len(items)-max)
}

// defaultDevices are the device nodes OCI runtimes create in every
// container (runtime-spec "Default Devices", plus /dev/console and ptmx).
var defaultDevices = []string{"null", "zero", "full", "random", "urandom", "tty", "console", "ptmx"}

// sensitiveDevices give direct access to kernel or host resources.
var sensitiveDevices = []string{"mem", "kmem", "port", "kmsg", "kvm", "nvram", "snapshot",
	"userfaultfd", "vhost-net", "vhost-vsock", "vfio/vfio", "fuse", "net/tun"}

// hostDevices lists device nodes beyond the defaults, most notable first:
// disks, then sensitive character devices, then other block devices
// (loop, ram, nbd) and the remaining character devices.
func hostDevices(fsys fs.FS) []string {
	var disks, sensitive, otherBlk, otherChr []string
	fs.WalkDir(fsys, "dev", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel := strings.TrimPrefix(p, "dev/")
		if d.IsDir() && (rel == "pts" || rel == "shm" || rel == "mqueue") {
			return fs.SkipDir
		}
		switch t := d.Type(); {
		case t&fs.ModeDevice == 0:
		case t&fs.ModeCharDevice == 0:
			if strings.HasPrefix(rel, "loop") || strings.HasPrefix(rel, "ram") || strings.HasPrefix(rel, "nbd") {
				otherBlk = append(otherBlk, rel)
			} else {
				disks = append(disks, rel)
			}
		case slices.Contains(defaultDevices, rel):
		case slices.Contains(sensitiveDevices, rel):
			sensitive = append(sensitive, rel)
		default:
			otherChr = append(otherChr, rel)
		}
		return nil
	})
	return slices.Concat(disks, sensitive, otherBlk, otherChr)
}

// maskedPaths are hidden (by mounting /dev/null or an empty tmpfs over them)
// by Docker, containerd, CRI-O and podman alike. Engine-specific extras such
// as Docker's /proc/interrupts and /proc/asound are left out so a default
// container from any engine has none exposed.
var maskedPaths = []string{
	"/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/sched_debug",
	"/proc/scsi", "/proc/timer_list", "/proc/timer_stats", "/sys/firmware",
}

// unmaskedPaths lists masked paths that exist but have nothing mounted over
// them. Paths the kernel doesn't provide are ignored.
func unmaskedPaths(fsys fs.FS, mounts []procfs.Mount) []string {
	var out []string
	for _, p := range maskedPaths {
		if _, err := fs.Stat(fsys, strings.TrimPrefix(p, "/")); err != nil {
			continue
		}
		if m, ok := procfs.MountFor(mounts, p); ok && m.Point == p {
			continue
		}
		out = append(out, p)
	}
	return out
}

func cgroup(fsys fs.FS, mounts []procfs.Mount, self string) Cgroup {
	var v1, v2 bool
	for _, m := range mounts {
		v1 = v1 || m.FSType == "cgroup"
		v2 = v2 || m.FSType == "cgroup2"
	}
	c := Cgroup{Version: "unknown"}
	switch {
	case v1 && v2:
		c.Version = "hybrid"
	case v1:
		c.Version = "v1"
	case v2:
		c.Version = "v2"
	}

	paths := map[string]string{} // controller -> path; "" is the v2 unified path
	for _, line := range strings.Split(self, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			paths[""] = parts[2]
		}
		for _, ctrl := range strings.Split(parts[1], ",") {
			paths[ctrl] = parts[2]
		}
	}

	if c.Version == "v2" {
		dir, ok := cgroupDir(mounts, "cgroup2", "", paths[""])
		c.Path = paths[""]
		if ok {
			c.MemoryMax = read(fsys, dir+"/memory.max")
			c.CPUMax = read(fsys, dir+"/cpu.max")
			c.PIDsMax = read(fsys, dir+"/pids.max")
		}
		return c
	}

	if dir, ok := cgroupDir(mounts, "cgroup", "memory", paths["memory"]); ok {
		c.Path = paths["memory"]
		c.MemoryMax = read(fsys, dir+"/memory.limit_in_bytes")
		// v1 reports "unlimited" as the largest page-aligned int64.
		if n, err := strconv.ParseInt(c.MemoryMax, 10, 64); err == nil && n >= 1<<62 {
			c.MemoryMax = "max"
		}
	}
	if dir, ok := cgroupDir(mounts, "cgroup", "cpu", paths["cpu"]); ok {
		quota, period := read(fsys, dir+"/cpu.cfs_quota_us"), read(fsys, dir+"/cpu.cfs_period_us")
		if quota == "-1" {
			quota = "max"
		}
		if quota != "" && period != "" {
			c.CPUMax = quota + " " + period
		}
	}
	if dir, ok := cgroupDir(mounts, "cgroup", "pids", paths["pids"]); ok {
		c.PIDsMax = read(fsys, dir+"/pids.max")
	}
	return c
}

// cgroupDir maps a cgroup path from /proc/self/cgroup to a directory under
// the matching cgroup mount, allowing for the mount's own root (which is "/"
// with a private cgroup namespace).
func cgroupDir(mounts []procfs.Mount, fstype, controller, cgPath string) (string, bool) {
	for _, m := range mounts {
		if m.FSType != fstype {
			continue
		}
		if controller != "" && !slices.Contains(strings.Split(m.SuperOpts, ","), controller) {
			continue
		}
		rel, ok := strings.CutPrefix(cgPath, m.Root)
		if !ok {
			continue
		}
		return strings.TrimPrefix(path.Join(m.Point, rel), "/"), true
	}
	return "", false
}
