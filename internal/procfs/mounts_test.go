package procfs

import (
	"slices"
	"testing"
)

// Excerpt of a default Docker container's mountinfo (test server).
const dockerMountinfo = `3684 3632 0:77 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/A
3686 3684 0:88 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
3689 3684 0:91 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
3690 3689 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot
3636 3686 0:88 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
3641 3686 0:89 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
3700 3684 259:2 /home/me/my\040dir /data rw,relatime - ext4 /dev/nvme0n1p2 rw
`

func TestParseMountinfo(t *testing.T) {
	m := ParseMountinfo(dockerMountinfo)
	if len(m) != 7 {
		t.Fatalf("got %d mounts", len(m))
	}
	if m[0].Point != "/" || m[0].FSType != "overlay" || m[0].ReadOnly() {
		t.Errorf("root = %+v", m[0])
	}
	if m[3].FSType != "cgroup2" || !slices.Contains(m[3].Options, "ro") || m[3].SuperOpts != "rw,nsdelegate,memory_recursiveprot" {
		t.Errorf("cgroup = %+v", m[3])
	}
	if m[5].Root != "/null" || m[5].Point != "/proc/kcore" {
		t.Errorf("kcore = %+v", m[5])
	}
	if m[6].Root != "/home/me/my dir" {
		t.Errorf("unescape: %q", m[6].Root)
	}
}

func TestMountFor(t *testing.T) {
	m := ParseMountinfo(dockerMountinfo)
	for path, want := range map[string]string{
		"/":                       "/",
		"/etc/passwd":             "/",
		"/proc/self/status":       "/proc",
		"/proc/sys":               "/proc/sys",
		"/proc/sys/kernel":        "/proc/sys",
		"/proc/sysrq-trigger":     "/proc",
		"/sys/fs/cgroup/pids.max": "/sys/fs/cgroup",
		"/sysfoo":                 "/",
	} {
		got, ok := MountFor(m, path)
		if !ok || got.Point != want {
			t.Errorf("MountFor(%q) = %q, want %q", path, got.Point, want)
		}
	}
}
