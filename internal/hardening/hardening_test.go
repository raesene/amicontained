package hardening

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/genuinetools/amicontained/internal/procfs"
)

// Captured on the test server (Docker 29, kernel 7.0, cgroup v2).
const defaultMountinfo = `1 0 0:77 / / rw,relatime - overlay overlay rw
2 1 0:88 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
3 1 0:89 / /dev rw,nosuid - tmpfs tmpfs rw
4 1 0:91 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
5 4 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw
6 2 0:88 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
7 2 0:93 / /proc/acpi ro,relatime - tmpfs tmpfs ro
8 2 0:89 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw
9 2 0:89 /null /proc/keys rw,nosuid - tmpfs tmpfs rw
10 2 0:89 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw
11 4 0:97 / /sys/firmware ro,relatime - tmpfs tmpfs ro
`

const privilegedMountinfo = `1 0 0:77 / / rw,relatime - overlay overlay rw
2 1 0:88 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
3 1 0:89 / /dev rw,nosuid - tmpfs tmpfs rw
4 1 0:91 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
5 4 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw
`

const readOnlyMountinfo = `1 0 0:77 / / ro,relatime - overlay overlay rw
4 1 0:91 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
5 4 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw
6 1 0:88 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
`

var allCaps = strings.Fields(`chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap
linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio
sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod
lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read
perfmon bpf checkpoint_restore`)

var dockerCaps = strings.Fields(`chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service
net_raw sys_chroot mknod audit_write setfcap`)

func chr() *fstest.MapFile { return &fstest.MapFile{Mode: fs.ModeDevice | fs.ModeCharDevice} }
func blk() *fstest.MapFile { return &fstest.MapFile{Mode: fs.ModeDevice} }
func file(s string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(s)}
}

// procFiles exist on the host kernel whether or not they are masked.
func baseFS() fstest.MapFS {
	return fstest.MapFS{
		"proc/sys/kernel/cap_last_cap": file("40\n"),
		"proc/kcore":                   file(""),
		"proc/keys":                    file(""),
		"proc/timer_list":              file(""),
		"proc/acpi/x":                  file(""),
		"proc/interrupts":              file(""), // masked by Docker only
		"sys/firmware/x":               file(""),
		"proc/self/cgroup":             file("0::/\n"),
		"sys/fs/cgroup/memory.max":     file("max\n"),
		"sys/fs/cgroup/cpu.max":        file("max 100000\n"),
		"sys/fs/cgroup/pids.max":       file("70360\n"),
		"dev/null":                     chr(),
		"dev/zero":                     chr(),
		"dev/tty":                      chr(),
		"dev/pts/0":                    chr(),
		"dev/pts/ptmx":                 chr(),
		"dev/shm/x":                    file(""),
	}
}

func indicators(r *Report) map[string]bool {
	m := map[string]bool{}
	for _, i := range r.Privileged.Indicators {
		m[i.Name] = i.Present
	}
	return m
}

func TestAssessDefault(t *testing.T) {
	r := assess(baseFS(), procfs.ParseMountinfo(defaultMountinfo), Inputs{Bounding: dockerCaps, LSMConfined: true})
	if r.Privileged.Present != 0 || r.Privileged.Verdict != "none present" {
		t.Errorf("default container: %+v", r.Privileged)
	}
	if r.RootFSReadOnly {
		t.Error("rootfs should be read-write")
	}
	want := Cgroup{Version: "v2", Path: "/", MemoryMax: "max", CPUMax: "max 100000", PIDsMax: "70360"}
	if r.Cgroup != want {
		t.Errorf("cgroup = %+v, want %+v", r.Cgroup, want)
	}
}

func TestAssessPrivileged(t *testing.T) {
	fsys := baseFS()
	fsys["dev/nvme0n1p2"] = blk()
	fsys["dev/loop0"] = blk()
	fsys["dev/mem"] = chr()
	fsys["dev/kmsg"] = chr()
	fsys["dev/input/event0"] = chr()
	r := assess(fsys, procfs.ParseMountinfo(privilegedMountinfo), Inputs{Bounding: allCaps, SeccompDisabled: true})
	got := indicators(r)
	for _, name := range []string{"host devices in /dev", "/sys mounted read-write", "/proc/sys mounted read-write",
		"masked paths exposed", "all capabilities in bounding set", "seccomp disabled", "no LSM confinement"} {
		if !got[name] {
			t.Errorf("%s: not present", name)
		}
	}
	if r.Privileged.Present != 7 || r.Privileged.Verdict != "looks privileged" {
		t.Errorf("privileged: %d %q", r.Privileged.Present, r.Privileged.Verdict)
	}
	for _, i := range r.Privileged.Indicators {
		switch i.Name {
		case "host devices in /dev":
			if i.Detail != "nvme0n1p2 kmsg mem loop0 input/event0" {
				t.Errorf("devices detail = %q", i.Detail)
			}
		case "masked paths exposed":
			if i.Detail != "/proc/acpi /proc/kcore /proc/keys /proc/timer_list /sys/firmware" {
				t.Errorf("masked detail = %q", i.Detail)
			}
		}
	}
}

func TestAssessUserNamespaceVerdict(t *testing.T) {
	r := assess(baseFS(), procfs.ParseMountinfo(defaultMountinfo), Inputs{Bounding: allCaps, LSMConfined: true, UserNamespace: true})
	if r.Privileged.Present != 1 || !strings.Contains(r.Privileged.Verdict, "user namespace") {
		t.Errorf("verdict = %d %q", r.Privileged.Present, r.Privileged.Verdict)
	}
}

func TestReadOnlyAndLimits(t *testing.T) {
	// docker run --read-only --memory 256m --cpus 1.5 --pids-limit 100
	fsys := baseFS()
	fsys["sys/fs/cgroup/memory.max"] = file("268435456\n")
	fsys["sys/fs/cgroup/cpu.max"] = file("150000 100000\n")
	fsys["sys/fs/cgroup/pids.max"] = file("100\n")
	r := assess(fsys, procfs.ParseMountinfo(readOnlyMountinfo), Inputs{LSMConfined: true})
	if !r.RootFSReadOnly {
		t.Error("rootfs should be read-only")
	}
	want := Cgroup{Version: "v2", Path: "/", MemoryMax: "268435456", CPUMax: "150000 100000", PIDsMax: "100"}
	if r.Cgroup != want {
		t.Errorf("cgroup = %+v, want %+v", r.Cgroup, want)
	}
}

func TestCgroupHostNamespace(t *testing.T) {
	// --cgroupns=host: the mount root is "/" and our path is the full one.
	const scope = "system.slice/docker-1a5b.scope"
	fsys := fstest.MapFS{
		"sys/fs/cgroup/" + scope + "/memory.max": file("1073741824"),
		"sys/fs/cgroup/" + scope + "/cpu.max":    file("max 100000"),
		"sys/fs/cgroup/" + scope + "/pids.max":   file("max"),
	}
	mounts := procfs.ParseMountinfo(defaultMountinfo)
	c := cgroup(fsys, mounts, "0::/"+scope+"\n")
	want := Cgroup{Version: "v2", Path: "/" + scope, MemoryMax: "1073741824", CPUMax: "max 100000", PIDsMax: "max"}
	if c != want {
		t.Errorf("cgroup = %+v, want %+v", c, want)
	}
}

func TestCgroupV1(t *testing.T) {
	mounts := procfs.ParseMountinfo(`1 0 0:1 / / rw - overlay overlay rw
20 1 0:20 / /sys/fs/cgroup/memory ro,nosuid - cgroup cgroup rw,memory
21 1 0:21 / /sys/fs/cgroup/cpu,cpuacct ro,nosuid - cgroup cgroup rw,cpu,cpuacct
22 1 0:22 / /sys/fs/cgroup/pids ro,nosuid - cgroup cgroup rw,pids
`)
	fsys := fstest.MapFS{
		"sys/fs/cgroup/memory/memory.limit_in_bytes":  file("9223372036854771712"),
		"sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us":  file("50000"),
		"sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us": file("100000"),
		"sys/fs/cgroup/pids/pids.max":                 file("max"),
	}
	c := cgroup(fsys, mounts, "12:pids:/\n11:memory:/\n10:cpu,cpuacct:/\n")
	want := Cgroup{Version: "v1", Path: "/", MemoryMax: "max", CPUMax: "50000 100000", PIDsMax: "max"}
	if c != want {
		t.Errorf("cgroup = %+v, want %+v", c, want)
	}
}

func TestAssessSandboxVerdict(t *testing.T) {
	r := assess(baseFS(), procfs.ParseMountinfo(privilegedMountinfo), Inputs{SeccompDisabled: true, Sandbox: "gvisor"})
	if !strings.Contains(r.Privileged.Verdict, "gvisor sandbox") {
		t.Errorf("verdict = %q", r.Privileged.Verdict)
	}
}
