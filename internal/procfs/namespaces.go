package procfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Namespace says whether we share a namespace with the host (the kernel's
// initial namespace of that type).
type Namespace struct {
	Type  string `json:"type"`
	Inode uint64 `json:"inode,omitempty"`
	// Host is true when we are in the initial namespace, i.e. not isolated.
	Host bool `json:"host"`
	// Exact is false when the answer rests on inode allocation order rather
	// than a number fixed by the kernel.
	Exact bool `json:"exact"`
	// Unsupported is true when the kernel lacks this namespace type, as
	// gVisor and some VM guest kernels lack time and cgroup namespaces.
	Unsupported bool   `json:"unsupported,omitempty"`
	Error       string `json:"error,omitempty"`
}

// NamespaceTypes is the order namespaces are reported in.
var NamespaceTypes = []string{"cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"}

// The kernel gives initial namespaces fixed proc inode numbers
// (include/linux/proc_ns.h): ipc/uts/user/pid/cgroup/time always, net and
// mnt on recent kernels.
var initialInodes = map[string]uint64{
	"ipc":    0xEFFFFFFF,
	"uts":    0xEFFFFFFE,
	"user":   0xEFFFFFFD,
	"pid":    0xEFFFFFFC,
	"cgroup": 0xEFFFFFFB,
	"time":   0xEFFFFFFA,
	"net":    0xEFFFFFF9,
	"mnt":    0xEFFFFFF8,
}

// Older kernels (verified on 6.1 and 6.12) allocate the initial net and mnt
// inodes dynamically, but as the first two numbers handed out, and they are
// never freed.
var legacyInitialInodes = map[string]uint64{
	"net": 0xF0000000,
	"mnt": 0xF0000001,
}

// Namespaces checks every namespace type via /proc/self/ns.
func Namespaces() []Namespace {
	inodes := map[string]uint64{}
	errs := map[string]error{}
	for _, t := range NamespaceTypes {
		link, err := os.Readlink("/proc/self/ns/" + t)
		if err == nil {
			inodes[t], err = parseNSLink(t, link)
		}
		if err != nil {
			errs[t] = err
		}
	}
	var uts unix.Utsname
	release := ""
	if unix.Uname(&uts) == nil {
		release = unix.ByteSliceToString(uts.Release[:])
	}
	// A missing link means the kernel lacks that type, unless the whole
	// directory is missing (no /proc).
	if _, err := os.Stat("/proc/self/ns"); err == nil {
		for t, err := range errs {
			if errors.Is(err, fs.ErrNotExist) {
				errs[t] = ErrUnsupported
			}
		}
	}
	return ClassifyNamespaces(inodes, errs, release)
}

// ErrUnsupported marks a namespace type the kernel does not have.
var ErrUnsupported = errors.New("not supported by this kernel")

func parseNSLink(t, link string) (uint64, error) {
	// "pid:[4026531836]"
	s, ok := strings.CutPrefix(link, t+":[")
	if !ok || !strings.HasSuffix(s, "]") {
		return 0, fmt.Errorf("unexpected namespace link %q", link)
	}
	return strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
}

// ClassifyNamespaces turns namespace inodes into host/private verdicts.
// release is the kernel release (uname -r).
func ClassifyNamespaces(inodes map[string]uint64, errs map[string]error, release string) []Namespace {
	// If net or mnt carries its fixed initial number, or the kernel is new
	// enough (7.0 verified; the exact version that introduced this is not
	// pinned down), a different number is definitely private.
	major, _, _ := strings.Cut(release, ".")
	m, _ := strconv.Atoi(major)
	fixedNetMnt := m >= 7 || inodes["net"] == initialInodes["net"] || inodes["mnt"] == initialInodes["mnt"]

	var out []Namespace
	for _, t := range NamespaceTypes {
		ns := Namespace{Type: t}
		if err := errs[t]; err != nil {
			if errors.Is(err, ErrUnsupported) {
				ns.Unsupported = true
			} else {
				ns.Error = err.Error()
			}
			out = append(out, ns)
			continue
		}
		ino := inodes[t]
		ns.Inode = ino
		switch legacy, hasLegacy := legacyInitialInodes[t]; {
		case ino == initialInodes[t]:
			ns.Host, ns.Exact = true, true
		case !hasLegacy || fixedNetMnt:
			ns.Exact = true
		case ino == legacy:
			ns.Host = true
		}
		out = append(out, ns)
	}
	return out
}

// HostPIDVisible reports whether kthreadd (PID 2 in the initial PID
// namespace) is visible, which only happens when sharing the host's PID
// namespace and procfs.
func HostPIDVisible() bool {
	b, err := os.ReadFile("/proc/2/status")
	return err == nil && ParseStatus(string(b))["Name"] == "kthreadd"
}
