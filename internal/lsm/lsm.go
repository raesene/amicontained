// Package lsm reports which Linux Security Modules are active, the labels
// they give this process, and whether Landlock is available.
package lsm

import (
	"errors"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Report is what Detect found.
type Report struct {
	// Active lists the LSMs in kernel order when Source is "securityfs" or
	// "lsm_list_modules"; when inferred it is partial.
	Active   []string `json:"active"`
	Source   string   `json:"source"`
	AppArmor *Label   `json:"apparmor,omitempty"`
	SELinux  *Label   `json:"selinux,omitempty"`
	Smack    *Label   `json:"smack,omitempty"`
	Landlock Landlock `json:"landlock"`
}

// Label is the security context an LSM has given this process.
type Label struct {
	Label string `json:"label"`
	// Confining is false for labels that impose no restrictions, such as
	// AppArmor "unconfined" or SELinux spc_t, or an SELinux in permissive mode.
	Confining bool   `json:"confining"`
	Note      string `json:"note,omitempty"`
}

// Landlock reports Landlock availability. The kernel offers no way to ask
// whether the current process is restricted by a Landlock ruleset.
type Landlock struct {
	Available bool   `json:"available"`
	ABI       int    `json:"abi,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Confined reports whether any LSM label confines this process.
func (r *Report) Confined() bool {
	for _, l := range []*Label{r.AppArmor, r.SELinux, r.Smack} {
		if l != nil && l.Confining {
			return true
		}
	}
	return false
}

// SafeToCall reports whether a syscall may be made, and if not why.
type SafeToCall func(name string) (bool, string)

// Detect inspects the running system.
func Detect(safe SafeToCall) *Report {
	return detect(os.DirFS("/"), safe, listModules, landlockABI)
}

func detect(fsys fs.FS, safe SafeToCall, list func() ([]uint64, error), landlock func() (int, error)) *Report {
	r := &Report{Active: []string{}}

	if ok, why := safe("landlock_create_ruleset"); !ok {
		r.Landlock.Error = why
	} else if abi, err := landlock(); err != nil {
		switch {
		case errors.Is(err, unix.EOPNOTSUPP):
			r.Landlock.Error = "built into the kernel but disabled at boot"
		case errors.Is(err, unix.ENOSYS):
			r.Landlock.Error = "not supported by the kernel"
		default:
			r.Landlock.Error = err.Error()
		}
	} else {
		r.Landlock = Landlock{Available: true, ABI: abi}
	}

	if b, err := fs.ReadFile(fsys, "sys/kernel/security/lsm"); err == nil {
		r.Active, r.Source = strings.Split(strings.TrimSpace(string(b)), ","), "securityfs"
	} else if ok, _ := safe("lsm_list_modules"); ok {
		if ids, err := list(); err == nil {
			for _, id := range ids {
				r.Active = append(r.Active, lsmName(id))
			}
			r.Source = "lsm_list_modules"
		}
	}
	if r.Source == "" {
		r.Source = "inferred"
		r.Active = infer(fsys, r.Landlock.Available)
	}

	active := func(name string) bool { return slices.Contains(r.Active, name) }
	if active("apparmor") {
		// attr/apparmor/ appeared in 5.1; before that attr/current is AppArmor's.
		l, err := readAttr(fsys, "proc/self/attr/apparmor/current")
		if err != nil {
			l, _ = readAttr(fsys, "proc/self/attr/current")
		}
		r.AppArmor = appArmorLabel(l)
	}
	if active("selinux") {
		l, _ := readAttr(fsys, "proc/self/attr/current")
		enforce, err := fs.ReadFile(fsys, "sys/fs/selinux/enforce")
		mode := ""
		if err == nil {
			mode = strings.TrimSpace(string(enforce))
		}
		r.SELinux = selinuxLabel(l, mode)
	}
	if active("smack") {
		l, _ := readAttr(fsys, "proc/self/attr/smack/current")
		r.Smack = &Label{Label: l, Confining: l != "" && l != "*" && l != "@"}
	}
	return r
}

// infer works out the active LSMs without securityfs or lsm_list_modules
// (both commonly unavailable in containers). The result is partial: it
// cannot see lockdown, IMA, EVM and other LSMs without a userspace trace.
func infer(fsys fs.FS, landlock bool) []string {
	active := []string{"capability"}
	if b, _ := fs.ReadFile(fsys, "sys/module/apparmor/parameters/enabled"); strings.TrimSpace(string(b)) == "Y" {
		active = append(active, "apparmor")
	}
	if _, err := fs.Stat(fsys, "sys/fs/selinux/enforce"); err == nil {
		active = append(active, "selinux")
	} else if l, _ := readAttr(fsys, "proc/self/attr/current"); !slices.Contains(active, "apparmor") && looksSELinux(l) {
		active = append(active, "selinux")
	}
	// Reading attr/smack/current fails with EINVAL unless Smack is active.
	if _, err := readAttr(fsys, "proc/self/attr/smack/current"); err == nil {
		active = append(active, "smack")
	}
	if _, err := fs.Stat(fsys, "proc/sys/kernel/yama"); err == nil {
		active = append(active, "yama")
	}
	if landlock {
		active = append(active, "landlock")
	}
	return active
}

func readAttr(fsys fs.FS, name string) (string, error) {
	b, err := fs.ReadFile(fsys, name)
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00\n")), err
}

// looksSELinux matches an SELinux context ("user:role:type[:level]") or
// "kernel", the context of every process when no policy is loaded.
func looksSELinux(l string) bool {
	return l == "kernel" || strings.Count(l, ":") >= 2
}

func appArmorLabel(l string) *Label {
	label := &Label{Label: l, Confining: true}
	switch {
	case l == "" || l == "unconfined":
		label.Label, label.Confining = "unconfined", false
	case strings.HasSuffix(l, " (unconfined)"):
		label.Confining = false
		label.Note = "profile in unconfined mode"
	case strings.HasSuffix(l, " (complain)"):
		label.Confining = false
		label.Note = "profile in complain mode: violations are logged, not denied"
	}
	return label
}

func selinuxLabel(l, enforce string) *Label {
	label := &Label{Label: l, Confining: true}
	parts := strings.Split(l, ":")
	switch {
	case l == "kernel":
		label.Confining = false
		label.Note = "no SELinux policy loaded"
	case len(parts) >= 3 && (parts[2] == "unconfined_t" || parts[2] == "spc_t" || parts[2] == "kernel_t"):
		label.Confining = false
		label.Note = parts[2] + " is unconfined"
	case enforce == "0":
		label.Confining = false
		label.Note = "SELinux is permissive"
	}
	return label
}

// LSM IDs from include/uapi/linux/lsm.h.
var lsmIDs = map[uint64]string{
	100: "capability",
	101: "selinux",
	102: "smack",
	103: "tomoyo",
	104: "apparmor",
	105: "yama",
	106: "loadpin",
	107: "safesetid",
	108: "lockdown",
	109: "bpf",
	110: "landlock",
	111: "ima",
	112: "evm",
	113: "ipe",
}

func lsmName(id uint64) string {
	if n, ok := lsmIDs[id]; ok {
		return n
	}
	return "lsm_" + strconv.FormatUint(id, 10)
}

// listModules calls lsm_list_modules(2) (Linux 6.8+).
func listModules() ([]uint64, error) {
	ids := make([]uint64, 32)
	size := uint32(len(ids) * 8)
	n, _, errno := unix.Syscall(unix.SYS_LSM_LIST_MODULES,
		uintptr(unsafe.Pointer(&ids[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return nil, errno
	}
	return ids[:n], nil
}

// landlockABI asks landlock_create_ruleset(2) for the ABI version.
func landlockABI() (int, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, errno
	}
	return int(abi), nil
}
