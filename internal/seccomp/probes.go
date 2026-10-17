//go:build linux

package seccomp

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// syscallEntry is one row of the generated per-architecture syscall table.
type syscallEntry struct {
	nr   int
	name string
}

// unknownSyscallNr is a syscall number that is not assigned on any supported
// architecture. Probing it reveals the policy's default action for syscalls
// the profile doesn't mention (e.g. runc/crun return ENOSYS for syscalls
// newer than the profile, Docker returns EPERM).
const unknownSyscallNr = 1000

// probeKind distinguishes how a probe's result is reported.
type probeKind int

const (
	kindSyscall probeKind = iota
	kindDefault
	kindArgument
)

// probe is a single syscall invocation to test against the active filter.
// args holds the first five arguments; the sixth is reserved for the cookie
// that our own notification filter matches on.
type probe struct {
	kind probeKind
	nr   int
	name string
	desc string
	args [5]uintptr
}

// argProbe describes a security-relevant syscall+argument combination that
// common profiles filter on argument values rather than syscall number.
type argProbe struct {
	name string
	desc string
	args [5]uintptr
}

// argProbes are only run with the user-notification method, where the
// syscall is never actually executed.
var argProbes = []argProbe{
	{"clone", "clone(SIGCHLD) - create a process", [5]uintptr{uintptr(unix.SIGCHLD)}},
	{"clone", "clone(CLONE_NEWUSER) - create a user namespace", [5]uintptr{unix.CLONE_NEWUSER | uintptr(unix.SIGCHLD)}},
	{"clone", "clone(CLONE_NEWNS) - create a mount namespace", [5]uintptr{unix.CLONE_NEWNS | uintptr(unix.SIGCHLD)}},
	{"unshare", "unshare(CLONE_NEWUSER) - create a user namespace", [5]uintptr{unix.CLONE_NEWUSER}},
	{"unshare", "unshare(CLONE_NEWNS) - create a mount namespace", [5]uintptr{unix.CLONE_NEWNS}},
	{"unshare", "unshare(CLONE_NEWNET) - create a network namespace", [5]uintptr{unix.CLONE_NEWNET}},
	{"personality", "personality(PER_LINUX)", [5]uintptr{0}},
	{"personality", "personality(ADDR_NO_RANDOMIZE) - disable ASLR", [5]uintptr{0x0040000}},
	{"socket", "socket(AF_VSOCK) - host/guest vsock", [5]uintptr{unix.AF_VSOCK, unix.SOCK_STREAM}},
	{"ioctl", "ioctl(TIOCSTI) - inject terminal input", [5]uintptr{0, unix.TIOCSTI}},
}

// syscallNumber looks up a syscall number by name in the native table.
func syscallNumber(name string) (int, bool) {
	for _, e := range syscallTable {
		if e.name == name {
			return e.nr, true
		}
	}
	return 0, false
}

// syscallName returns the native name for a syscall number.
func syscallName(nr int) string {
	for _, e := range syscallTable {
		if e.nr == nr {
			return e.name
		}
	}
	return fmt.Sprintf("syscall_%d", nr)
}

// buildProbes returns the ordered probe list. Parent and child both call it
// and refer to probes by index, so it must be deterministic.
func buildProbes(withArgs bool) []probe {
	probes := []probe{{
		kind: kindDefault,
		nr:   unknownSyscallNr,
		name: fmt.Sprintf("syscall_%d", unknownSyscallNr),
		desc: "unassigned syscall number",
	}}
	for _, e := range syscallTable {
		probes = append(probes, probe{kind: kindSyscall, nr: e.nr, name: e.name})
	}
	if withArgs {
		for _, ap := range argProbes {
			nr, ok := syscallNumber(ap.name)
			if !ok {
				continue
			}
			probes = append(probes, probe{kind: kindArgument, nr: nr, name: ap.name, desc: ap.desc, args: ap.args})
		}
	}
	return probes
}

// seccompExempt lists syscalls the kernel never passes to seccomp filters
// (see seccomp_uprobe_exception in kernel/seccomp.c). Probing them would run
// them for real, and no policy can block them anyway.
var seccompExempt = map[string]bool{"uretprobe": true, "uprobe": true}

// heuristicUnsafe lists syscalls the errno-heuristic fallback must never
// execute, because with zero arguments they hang, terminate or fork the
// prober, or change state outside the prober process (hostname, kexec image,
// process accounting, controlling terminal).
var heuristicUnsafe = map[string]bool{
	"rt_sigreturn": true, "select": true, "pause": true, "pselect6": true, "ppoll": true,
	"exit": true, "exit_group": true,
	"clone": true, "clone3": true, "fork": true, "vfork": true,
	"seccomp": true, "sync": true, "tkill": true, "ptrace": true,
	"sethostname": true, "setdomainname": true,
	"kexec_load": true, "kexec_file_load": true, "acct": true, "vhangup": true, "reboot": true,
	"msgget": true, "restart_syscall": true,
}
