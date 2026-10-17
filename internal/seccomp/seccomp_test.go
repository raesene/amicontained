//go:build linux

package seccomp

import (
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// outerFilterEnv makes the test binary install testOuterRules as an "outer"
// policy, run Probe and print the report as JSON.
const outerFilterEnv = "AMICONTAINED_TEST_OUTER_FILTER"

func TestMain(m *testing.M) {
	if IsChild() {
		RunChild()
	}
	if method, ok := os.LookupEnv(outerFilterEnv); ok {
		runUnderOuterFilter(Method(method))
	}
	os.Exit(m.Run())
}

type outerRule struct {
	name   string
	action uint32
}

// testOuterRules exercises every action the prober must distinguish.
// Syscalls chosen are ones the Go runtime and test harness never call.
var testOuterRules = []outerRule{
	{"mount", unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{"pivot_root", unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{"keyctl", unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
	{"add_key", unix.SECCOMP_RET_ERRNO | uint32(unix.EACCES)},
	{"acct", unix.SECCOMP_RET_KILL_PROCESS},
	{"swapon", unix.SECCOMP_RET_KILL_THREAD},
	{"setns", unix.SECCOMP_RET_TRAP},
	{"syslog", unix.SECCOMP_RET_LOG},
}

// cloneNewUserBlocked adds an argument filter: clone with CLONE_NEWUSER set
// returns EPERM, other clones are allowed (mirrors Docker's default profile).
const cloneNewUserErrno = unix.EPERM

func runUnderOuterFilter(method Method) {
	if err := installOuterFilter(); err != nil {
		os.Stderr.WriteString("installing outer filter: " + err.Error() + "\n")
		os.Exit(3)
	}
	report := Probe(Options{Method: method})
	json.NewEncoder(os.Stdout).Encode(report)
	os.Exit(0)
}

func installOuterFilter() error {
	stmt := func(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
	jeq := func(k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: jt, Jf: jf, K: k}
	}
	ld := uint16(unix.BPF_LD | unix.BPF_W | unix.BPF_ABS)
	ret := uint16(unix.BPF_RET | unix.BPF_K)

	cloneNr, _ := syscallNumber("clone")
	prog := []unix.SockFilter{
		stmt(ld, offArch),
		jeq(auditArch, 1, 0),
		stmt(ret, unix.SECCOMP_RET_ALLOW),
		stmt(ld, 0), // nr
	}
	for _, r := range testOuterRules {
		nr, ok := syscallNumber(r.name)
		if !ok {
			continue
		}
		prog = append(prog, jeq(uint32(nr), 0, 1), stmt(ret, r.action))
	}
	// clone: block if (args[0] & CLONE_NEWUSER) != 0.
	prog = append(prog,
		jeq(uint32(cloneNr), 0, 3),
		stmt(ld, 16), // args[0] low word
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jt: 0, Jf: 1, K: unix.CLONE_NEWUSER},
		stmt(ret, unix.SECCOMP_RET_ERRNO|uint32(cloneNewUserErrno)),
		stmt(ret, unix.SECCOMP_RET_ALLOW),
	)

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	// TSYNC so every runtime thread (and therefore every forked child) is filtered.
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return errno
	}
	return nil
}

func probeUnderOuterFilter(t *testing.T, method Method) *Report {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), outerFilterEnv+"="+string(method))
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running under outer filter: %v", err)
	}
	var report Report
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decoding report: %v\n%s", err, out)
	}
	return &report
}

func resultsByName(rs []Result) map[string]Result {
	m := map[string]Result{}
	for _, r := range rs {
		m[r.Syscall] = r
	}
	return m
}

func TestNotifyProbeUnderOuterFilter(t *testing.T) {
	if !supportedArch {
		t.Skip("unsupported architecture")
	}
	report := probeUnderOuterFilter(t, MethodNotify)
	if report.Method != MethodNotify {
		t.Skipf("user notification unavailable here: %v", report.Warnings)
	}
	if report.Mode != ModeFiltering || report.Filters < 1 {
		t.Errorf("mode = %s filters = %d, want filtering with >= 1 filter", report.Mode, report.Filters)
	}

	want := map[string]Result{
		"mount":      {Action: ActionErrno, Errno: "EPERM"},
		"pivot_root": {Action: ActionErrno, Errno: "EPERM"},
		"keyctl":     {Action: ActionErrno, Errno: "ENOSYS"},
		"add_key":    {Action: ActionErrno, Errno: "EACCES"},
		"acct":       {Action: ActionKill},
		"swapon":     {Action: ActionKill},
		"setns":      {Action: ActionTrap},
	}
	var gotBlocked []string
	for _, b := range report.Blocked() {
		gotBlocked = append(gotBlocked, b.Syscall)
	}
	sort.Strings(gotBlocked)
	var wantBlocked []string
	for name := range want {
		wantBlocked = append(wantBlocked, name)
	}
	sort.Strings(wantBlocked)
	if len(gotBlocked) != len(wantBlocked) {
		t.Errorf("blocked = %v, want exactly %v", gotBlocked, wantBlocked)
	}

	got := resultsByName(report.Syscalls)
	for name, w := range want {
		g := got[name]
		if g.Action != w.Action || g.Errno != w.Errno {
			t.Errorf("%s: got %s %s (%s), want %s %s", name, g.Action, g.Errno, g.Detail, w.Action, w.Errno)
		}
	}
	// SECCOMP_RET_LOG lets the call run, so it must read as allowed.
	if g := got["syslog"]; g.Action != ActionAllow {
		t.Errorf("syslog (RET_LOG): got %s, want allow", g.Action)
	}
	// Syscalls the old prober had to skip are now probed safely.
	for _, name := range []string{"exit_group", "rt_sigreturn", "vfork", "seccomp", "pause"} {
		if g, ok := got[name]; ok && g.Action != ActionAllow {
			t.Errorf("%s: got %s, want allow", name, g.Action)
		}
	}

	if _, ok := syscallNumber("uretprobe"); ok && got["uretprobe"].Action != ActionExempt {
		t.Errorf("uretprobe: got %s, want exempt", got["uretprobe"].Action)
	}

	if report.DefaultAction == nil || report.DefaultAction.Action != ActionAllow {
		t.Errorf("default action = %+v, want allow", report.DefaultAction)
	}

	args := map[string]Result{}
	for _, a := range report.ArgumentChecks {
		args[a.Args] = a
	}
	if a := args[argProbes[0].desc]; a.Action != ActionAllow {
		t.Errorf("%s: got %s, want allow", argProbes[0].desc, a.Action)
	}
	if a := args[argProbes[1].desc]; a.Action != ActionErrno || a.Errno != "EPERM" {
		t.Errorf("%s: got %s %s, want errno EPERM", argProbes[1].desc, a.Action, a.Errno)
	}
}

func TestHeuristicProbeUnderOuterFilter(t *testing.T) {
	if !supportedArch {
		t.Skip("unsupported architecture")
	}
	report := probeUnderOuterFilter(t, MethodHeuristic)
	if report.Method != MethodHeuristic {
		t.Fatalf("method = %s, warnings %v", report.Method, report.Warnings)
	}
	got := resultsByName(report.Syscalls)
	if g := got["pivot_root"]; g.Action != ActionErrno || g.Errno != "EPERM" {
		t.Errorf("pivot_root: got %s %s, want errno EPERM", g.Action, g.Errno)
	}
	if g := got["acct"]; g.Action != ActionSkipped {
		t.Errorf("acct: got %s, want skipped (unsafe to execute)", g.Action)
	}
	if g := got["setns"]; g.Action != ActionTrap {
		t.Errorf("setns: got %s, want trap", g.Action)
	}
	// The outer filter allows unassigned numbers, so the kernel answers
	// ENOSYS, which the heuristic cannot attribute.
	if d := report.DefaultAction; d == nil || d.Action != ActionUnknown {
		t.Errorf("default action = %+v, want unknown", d)
	}
	if len(report.ArgumentChecks) != 0 {
		t.Errorf("heuristic must not run argument probes, got %d", len(report.ArgumentChecks))
	}
}

func TestParseStatus(t *testing.T) {
	tests := []struct {
		status  string
		mode    Mode
		filters int
	}{
		{"Name:\tx\nSeccomp:\t0\nSeccomp_filters:\t0\n", ModeDisabled, 0},
		{"Seccomp:\t1\n", ModeStrict, 0},
		{"NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t3\n", ModeFiltering, 3},
		{"Name:\tx\n", ModeUnsupported, 0},
	}
	for _, tt := range tests {
		mode, filters := parseStatus(tt.status)
		if mode != tt.mode || filters != tt.filters {
			t.Errorf("parseStatus(%q) = %s, %d; want %s, %d", tt.status, mode, filters, tt.mode, tt.filters)
		}
	}
}

func TestSyscallTable(t *testing.T) {
	if !supportedArch {
		t.Skip("unsupported architecture")
	}
	names := map[string]bool{}
	for i, e := range syscallTable {
		if i > 0 && e.nr <= syscallTable[i-1].nr {
			t.Fatalf("table not strictly sorted at %d (%d after %d)", i, e.nr, syscallTable[i-1].nr)
		}
		if names[e.name] {
			t.Errorf("duplicate name %s", e.name)
		}
		names[e.name] = true
		if e.nr == unknownSyscallNr {
			t.Errorf("unknownSyscallNr %d is assigned to %s", e.nr, e.name)
		}
	}
	for _, name := range []string{"read", "clone", "unshare", "mount", "bpf", "io_uring_setup", "open_tree_attr"} {
		if !names[name] {
			t.Errorf("table missing %s", name)
		}
	}
	for _, ap := range argProbes {
		if !names[ap.name] {
			t.Errorf("argument probe %q references unknown syscall", ap.desc)
		}
	}
	for name := range heuristicUnsafe {
		if _, ok := syscallNumber(name); !ok {
			t.Logf("heuristicUnsafe entry %s not present on this arch", name)
		}
	}
}

func TestNotifyFilterJumpsInBounds(t *testing.T) {
	prog := notifyFilter()
	for i, ins := range prog {
		if ins.Code&0x07 == unix.BPF_JMP {
			for _, off := range []uint8{ins.Jt, ins.Jf} {
				if target := i + 1 + int(off); target >= len(prog) {
					t.Errorf("instruction %d jumps out of bounds to %d", i, target)
				}
			}
		}
	}
	if last := prog[len(prog)-1]; last.Code != unix.BPF_RET|unix.BPF_K || last.K != unix.SECCOMP_RET_ALLOW {
		t.Errorf("filter must end with RET ALLOW, got %+v", last)
	}
}

func TestHeuristicClassifier(t *testing.T) {
	errnoResult := func(e unix.Errno) rawResult { return rawResult{done: true, verdict: "errno", errno: int(e)} }
	tests := []struct {
		name        string
		calibration rawResult
		in          rawResult
		want        string
	}{
		{"eperm blocked", errnoResult(unix.ENOSYS), errnoResult(unix.EPERM), "errno"},
		{"eacces blocked", errnoResult(unix.ENOSYS), errnoResult(unix.EACCES), "errno"},
		{"efault allowed", errnoResult(unix.ENOSYS), errnoResult(unix.EFAULT), "allow"},
		{"enosys ambiguous", errnoResult(unix.ENOSYS), errnoResult(unix.ENOSYS), "allow"},
		{"custom default errno", errnoResult(unix.EIO), errnoResult(unix.EIO), "errno"},
		{"success", errnoResult(unix.ENOSYS), rawResult{done: true, verdict: "ok"}, "ok"},
	}
	for _, tt := range tests {
		if got := heuristicClassifier(tt.calibration)(tt.in).verdict; got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestDisabledModeReportsNothingBlocked(t *testing.T) {
	mode, _ := parseStatus(mustRead(t, "/proc/self/status"))
	if mode != ModeDisabled {
		t.Skipf("test process is under seccomp mode %s", mode)
	}
	report := Probe(Options{Method: MethodAuto})
	if report.Method != MethodNone || len(report.Blocked()) != 0 {
		t.Errorf("disabled seccomp: method %s, blocked %v", report.Method, report.Blocked())
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSafeToCall(t *testing.T) {
	r := &Report{Mode: ModeFiltering, Syscalls: []Result{
		{Syscall: "landlock_create_ruleset", Action: ActionAllow},
		{Syscall: "lsm_list_modules", Action: ActionErrno, Errno: "ENOSYS"},
		{Syscall: "kexec_load", Action: ActionKill},
		{Syscall: "uretprobe", Action: ActionExempt},
	}}
	for name, want := range map[string]bool{
		"landlock_create_ruleset": true,
		"lsm_list_modules":        false,
		"kexec_load":              false,
		"uretprobe":               false,
		"not_a_syscall":           false,
	} {
		if got, why := r.SafeToCall(name); got != want || (!got && why == "") {
			t.Errorf("SafeToCall(%s) = %t %q, want %t", name, got, why, want)
		}
	}
	if ok, _ := (&Report{Mode: ModeDisabled}).SafeToCall("anything"); !ok {
		t.Error("disabled mode: want safe")
	}
	if ok, _ := (&Report{Mode: ModeStrict}).SafeToCall("anything"); ok {
		t.Error("strict mode: want unsafe")
	}
}
