//go:build linux

// Package seccomp determines which syscalls the active seccomp policy blocks.
//
// The primary method never executes the probed syscalls. A child process
// stacks its own filter that returns SECCOMP_RET_USER_NOTIF for probe calls
// (tagged with a cookie argument) on top of the inherited policy. The kernel
// applies the highest-precedence action across all filters, so:
//
//   - if the outer policy returns ERRNO, the probe sees that errno;
//   - if it kills or traps, the child dies with SIGSYS;
//   - if it allows, our filter fires and our supervisor answers the
//     notification with a sentinel errno instead of running the syscall.
//
// This separates seccomp decisions from capability, LSM and kernel errors
// and makes every syscall safe to probe. If notification filters are not
// available (kernel < 5.0, or seccomp/prctl blocked), an errno heuristic is
// used and the report says so.
package seccomp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The syscall tables are generated from golang.org/x/sys; rerun after bumping it.
//go:generate go run ./gen -arch amd64 -o zsyscalls_linux_amd64.go
//go:generate go run ./gen -arch arm64 -o zsyscalls_linux_arm64.go

// Mode is the process's seccomp mode as reported by /proc/self/status.
type Mode string

const (
	ModeDisabled    Mode = "disabled"
	ModeStrict      Mode = "strict"
	ModeFiltering   Mode = "filtering"
	ModeUnsupported Mode = "unsupported"
)

// Method is how syscall verdicts were determined.
type Method string

const (
	MethodAuto      Method = "auto"
	MethodNotify    Method = "user-notification"
	MethodHeuristic Method = "errno-heuristic"
	MethodNone      Method = "none"
)

// Action is the verdict of the seccomp policy for one probe.
type Action string

const (
	ActionAllow   Action = "allow"
	ActionErrno   Action = "errno"
	ActionKill    Action = "kill"
	ActionTrap    Action = "trap"
	ActionSkipped Action = "skipped"
	ActionExempt  Action = "exempt"
	ActionUnknown Action = "unknown"
)

// Result is the verdict for a single syscall probe.
type Result struct {
	Syscall string `json:"syscall"`
	Number  int    `json:"number"`
	Args    string `json:"args,omitempty"`
	Action  Action `json:"action"`
	Errno   string `json:"errno,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Blocked reports whether the policy prevented the syscall from running.
func (r Result) Blocked() bool {
	return r.Action == ActionErrno || r.Action == ActionKill || r.Action == ActionTrap
}

// Report is the outcome of a seccomp assessment.
type Report struct {
	Mode           Mode     `json:"mode"`
	Filters        int      `json:"filters,omitempty"`
	Method         Method   `json:"method"`
	Warnings       []string `json:"warnings,omitempty"`
	DefaultAction  *Result  `json:"default_action,omitempty"`
	Syscalls       []Result `json:"syscalls,omitempty"`
	ArgumentChecks []Result `json:"argument_checks,omitempty"`
}

// Blocked returns the syscalls the policy blocks.
func (r *Report) Blocked() []Result {
	var blocked []Result
	for _, s := range r.Syscalls {
		if s.Blocked() {
			blocked = append(blocked, s)
		}
	}
	return blocked
}

// ArgumentCheck returns the argument probe for call, e.g.
// "unshare(CLONE_NEWUSER)", if one was run.
func (r *Report) ArgumentCheck(call string) (Result, bool) {
	for _, a := range r.ArgumentChecks {
		if a.Args == call || strings.HasPrefix(a.Args, call+" ") {
			return a, true
		}
	}
	return Result{}, false
}

// SafeToCall reports whether other checks may make syscall name for real
// without risking a KILL or TRAP action, and if not, why. It assumes the
// policy does not filter on the arguments the caller will use.
func (r *Report) SafeToCall(name string) (bool, string) {
	switch r.Mode {
	case ModeDisabled, ModeUnsupported:
		return true, ""
	case ModeStrict:
		return false, "seccomp strict mode"
	}
	for _, s := range r.Syscalls {
		if s.Syscall != name {
			continue
		}
		switch s.Action {
		case ActionAllow:
			return true, ""
		case ActionErrno:
			return false, "blocked by seccomp (" + s.Errno + ")"
		case ActionKill, ActionTrap:
			return false, "blocked by seccomp (" + string(s.Action) + ")"
		}
		return false, "seccomp verdict " + string(s.Action)
	}
	return false, "not probed by seccomp check"
}

// Options controls Probe.
type Options struct {
	// Method selects the probing method; MethodAuto tries user
	// notification and falls back to the heuristic.
	Method Method
	// Debug, if non-nil, receives per-probe progress.
	Debug io.Writer
}

// Probe assesses the seccomp policy applied to the current process.
func Probe(opts Options) *Report {
	report := &Report{Method: MethodNone}
	status, _ := os.ReadFile("/proc/self/status")
	report.Mode, report.Filters = parseStatus(string(status))

	if opts.Method == MethodNone {
		return report
	}
	switch report.Mode {
	case ModeDisabled:
		report.Warnings = append(report.Warnings, "seccomp is disabled: no syscalls are blocked by seccomp (other layers such as capabilities or LSMs may still deny them)")
		return report
	case ModeStrict:
		report.Warnings = append(report.Warnings, "strict mode: only read, write, _exit and sigreturn are permitted")
		return report
	case ModeUnsupported:
		report.Warnings = append(report.Warnings, "kernel does not report a seccomp mode")
		return report
	}
	if !supportedArch {
		report.Warnings = append(report.Warnings, "syscall probing is not supported on this architecture")
		return report
	}

	if opts.Method == MethodAuto || opts.Method == MethodNotify {
		probes := buildProbes(true)
		raw, err := runProbes(MethodNotify, probes, opts.Debug)
		if err == nil {
			report.Method = MethodNotify
			fillReport(report, probes, raw, nil)
			return report
		}
		report.Warnings = append(report.Warnings, fmt.Sprintf("user-notification probe unavailable: %v", err))
		if opts.Method == MethodNotify {
			return report
		}
	}

	probes := buildProbes(false)
	raw, err := runProbes(MethodHeuristic, probes, opts.Debug)
	if err != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("heuristic probe failed: %v", err))
		return report
	}
	report.Method = MethodHeuristic
	report.Warnings = append(report.Warnings, "results are an errno heuristic: syscalls were really executed with zero arguments, "+
		"EPERM/EACCES may come from capabilities or LSMs rather than seccomp, and blocks returning other errnos may be missed")
	fillReport(report, probes, raw, heuristicClassifier(raw[0]))
	// Without notification the kernel's own ENOSYS for an unassigned number
	// looks identical to a policy returning ENOSYS.
	if d := report.DefaultAction; d != nil && d.Errno == "ENOSYS" {
		d.Action, d.Errno, d.Detail = ActionUnknown, "", "ENOSYS: indistinguishable from the kernel's response without user notification"
	}
	return report
}

func parseStatus(status string) (Mode, int) {
	mode, filters := ModeUnsupported, 0
	for _, line := range strings.Split(status, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "Seccomp":
			switch val {
			case "0":
				mode = ModeDisabled
			case "1":
				mode = ModeStrict
			case "2":
				mode = ModeFiltering
			}
		case "Seccomp_filters":
			filters, _ = strconv.Atoi(val)
		}
	}
	return mode, filters
}

// rawResult is what the parent learned about one probe.
type rawResult struct {
	done    bool
	verdict string // allow, errno, ok, timeout, skipped, exempt, kill, trap, unknown
	errno   int
	detail  string
}

func fillReport(report *Report, probes []probe, raw []rawResult, classify func(rawResult) rawResult) {
	for i, p := range probes {
		rr := raw[i]
		if classify != nil && p.kind != kindDefault {
			rr = classify(rr)
		}
		res := Result{Syscall: p.name, Number: p.nr, Args: p.desc, Detail: rr.detail}
		switch rr.verdict {
		case "allow", "ok", "timeout":
			res.Action = ActionAllow
		case "errno":
			res.Action = ActionErrno
			res.Errno = errnoName(rr.errno)
		case "kill":
			res.Action = ActionKill
		case "trap":
			res.Action = ActionTrap
		case "skipped":
			res.Action = ActionSkipped
		case "exempt":
			res.Action = ActionExempt
			res.Detail = "the kernel exempts this syscall from seccomp filtering"
		default:
			res.Action = ActionUnknown
		}
		switch p.kind {
		case kindDefault:
			res.Args = ""
			report.DefaultAction = &res
		case kindSyscall:
			report.Syscalls = append(report.Syscalls, res)
		case kindArgument:
			report.ArgumentChecks = append(report.ArgumentChecks, res)
		}
	}
}

// heuristicClassifier turns raw errnos from really-executed syscalls into a
// best guess. EPERM/EACCES count as blocked, as does the errno an unassigned
// syscall number returns (the policy's default action) unless that is ENOSYS,
// which the kernel also returns for unimplemented syscalls.
func heuristicClassifier(calibration rawResult) func(rawResult) rawResult {
	defaultErrno := 0
	if calibration.verdict == "errno" && calibration.errno != int(unix.ENOSYS) {
		defaultErrno = calibration.errno
	}
	return func(rr rawResult) rawResult {
		if rr.verdict != "errno" {
			return rr
		}
		e := rr.errno
		if e == int(unix.EPERM) || e == int(unix.EACCES) || (defaultErrno != 0 && e == defaultErrno) {
			return rr
		}
		rr.verdict = "allow"
		rr.detail = "returned " + errnoName(e)
		return rr
	}
}

func errnoName(e int) string {
	if name := unix.ErrnoName(unix.Errno(e)); name != "" {
		return name
	}
	return strconv.Itoa(e)
}

const (
	startupTimeout = 10 * time.Second
	probeTimeout   = 3 * time.Second
	pollInterval   = 250 * time.Millisecond
)

// runProbes runs probe children until every probe has a verdict. A child
// that dies mid-run is restarted after the probe that killed it.
func runProbes(method Method, probes []probe, debug io.Writer) ([]rawResult, error) {
	raw := make([]rawResult, len(probes))
	for next := 0; next < len(probes); {
		n, err := runChild(method, probes, next, raw, debug)
		if err != nil {
			return nil, err
		}
		next = n
	}
	return raw, nil
}

// runChild starts one probe child at index start and returns the index to
// resume from.
func runChild(method Method, probes []probe, start int, raw []rawResult, debug io.Writer) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return start, fmt.Errorf("locating own executable: %w", err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return start, err
	}
	defer pr.Close()

	var stderr bytes.Buffer
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s:%d", childEnv, method, start), "GOTRACEBACK=single")
	cmd.ExtraFiles = []*os.File{pw}
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		pw.Close()
		return start, fmt.Errorf("starting probe process: %w", err)
	}
	pw.Close()

	lines := make(chan string)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()

	next, tid, deadTicks := start, 0, 0
	ready, hung, threadGone := false, false, false
	var setupErr error
	deadline := time.Now().Add(startupTimeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

read:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				break read
			}
			deadline = time.Now().Add(probeTimeout)
			verb, rest, _ := strings.Cut(line, " ")
			switch verb {
			case "ready":
				ready = true
				tid, _ = strconv.Atoi(rest)
			case "setup-error":
				setupErr = errors.New(rest)
			case "r":
				idx, rr, err := parseResultLine(rest)
				if err != nil || idx < 0 || idx >= len(raw) {
					continue
				}
				raw[idx] = rr
				next = idx + 1
				if debug != nil {
					fmt.Fprintf(debug, "seccomp: probe %d %s%s -> %s %s\n", idx, probes[idx].name, argSuffix(probes[idx]), rr.verdict, errnoSuffix(rr))
				}
			}
		case <-ticker.C:
			// KILL_THREAD leaves the process alive but silent: notice the
			// probing thread disappearing rather than waiting for a timeout.
			// Require two consecutive sightings so a child that is merely
			// exiting normally gets a chance to deliver EOF first.
			if ready && tid != 0 && threadDead(cmd.Process.Pid, tid) {
				deadTicks++
			} else {
				deadTicks = 0
			}
			if deadTicks >= 2 {
				threadGone = true
			} else if deadTicks > 0 || time.Now().Before(deadline) {
				continue
			} else {
				hung = true
			}
			cmd.Process.Kill()
			go func() {
				for range lines {
				}
			}()
			break read
		}
	}
	waitErr := cmd.Wait()

	if setupErr != nil {
		return start, setupErr
	}
	if next >= len(raw) {
		return next, nil
	}
	if !ready {
		return start, fmt.Errorf("probe process exited before starting (%v): %s", waitErr, firstLine(stderr.String()))
	}

	// The probe at index next terminated the child.
	rr := rawResult{done: true}
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	switch {
	case threadGone:
		rr.verdict, rr.detail = "kill", "probing thread killed (SECCOMP_RET_KILL_THREAD)"
	case hung:
		rr.verdict, rr.detail = "unknown", "no response from probe"
	case ws.Signaled() && ws.Signal() == unix.SIGSYS:
		rr.verdict, rr.detail = "kill", "process killed by SIGSYS (SECCOMP_RET_KILL_PROCESS)"
	case strings.Contains(stderr.String(), "SIGSYS"):
		rr.verdict, rr.detail = "trap", "SIGSYS delivered (SECCOMP_RET_TRAP)"
	default:
		rr.verdict, rr.detail = "unknown", fmt.Sprintf("probe process terminated: %v", waitErr)
	}
	raw[next] = rr
	if debug != nil {
		fmt.Fprintf(debug, "seccomp: probe %d %s%s -> %s (%s)\n", next, probes[next].name, argSuffix(probes[next]), rr.verdict, rr.detail)
	}
	return next + 1, nil
}

func parseResultLine(s string) (int, rawResult, error) {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return 0, rawResult{}, fmt.Errorf("malformed result %q", s)
	}
	idx, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, rawResult{}, err
	}
	rr := rawResult{done: true, verdict: fields[1]}
	if rr.verdict == "errno" && len(fields) > 2 {
		rr.errno, _ = strconv.Atoi(fields[2])
	}
	return idx, rr, nil
}

// threadDead reports whether thread tid of process pid has exited or is a
// zombie.
func threadDead(pid, tid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/stat", pid, tid))
	if err != nil {
		return true
	}
	// The state field follows the parenthesised comm, which may contain spaces.
	if i := bytes.LastIndexByte(stat, ')'); i >= 0 && i+2 < len(stat) {
		state := stat[i+2]
		return state == 'Z' || state == 'X'
	}
	return false
}

func argSuffix(p probe) string {
	if p.kind == kindArgument {
		return " [" + p.desc + "]"
	}
	return ""
}

func errnoSuffix(rr rawResult) string {
	if rr.verdict == "errno" {
		return errnoName(rr.errno)
	}
	return ""
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}
