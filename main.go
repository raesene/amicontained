package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/genuinetools/amicontained/internal/container"
	"github.com/genuinetools/amicontained/internal/hardening"
	"github.com/genuinetools/amicontained/internal/lsm"
	"github.com/genuinetools/amicontained/internal/procfs"
	"github.com/genuinetools/amicontained/internal/seccomp"
	"github.com/genuinetools/amicontained/internal/sockets"
	"github.com/genuinetools/amicontained/version"
)

var (
	debug         bool
	jsonOutput    bool
	seccompMethod string
	socketMode    sockets.Mode
)

// report is everything amicontained found, in output order.
type report struct {
	Runtime        *container.Runtime   `json:"runtime"`
	Namespaces     []procfs.Namespace   `json:"namespaces"`
	HostPIDVisible bool                 `json:"host_pid_visible"`
	UserMappings   []procfs.UserMapping `json:"user_mappings,omitempty"`
	NoNewPrivs     *bool                `json:"no_new_privs"`
	LSM            *lsm.Report          `json:"lsm"`
	Capabilities   *procfs.Capabilities `json:"capabilities"`
	CapsError      string               `json:"capabilities_error,omitempty"`
	Hardening      *hardening.Report    `json:"hardening"`
	Sockets        *sockets.Report      `json:"sockets"`
	Seccomp        *seccomp.Report      `json:"seccomp"`
}

func main() {
	// A re-executed copy of ourselves probing the seccomp policy.
	if seccomp.IsChild() {
		seccomp.RunChild()
		return
	}

	fs := flag.NewFlagSet("amicontained", flag.ExitOnError)
	fs.BoolVar(&debug, "d", false, "enable debug logging")
	fs.BoolVar(&jsonOutput, "json", false, "output results as JSON")
	fs.StringVar(&seccompMethod, "seccomp-method", "auto", "seccomp probing method: auto, notify, heuristic or none")
	sockMode := fs.String("sockets", "scan", "socket discovery: scan (well-known paths plus a bounded filesystem walk), known (well-known paths only) or none")
	showVersion := fs.Bool("version", false, "print version information and exit")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "amicontained - a container introspection tool.\n\nUsage: amicontained [flags]\n       amicontained version\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])

	switch {
	case *showVersion || (fs.NArg() == 1 && fs.Arg(0) == "version"):
		printVersion(os.Stdout)
		return
	case fs.NArg() > 0:
		fmt.Fprintf(os.Stderr, "amicontained: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		os.Exit(2)
	}

	method, err := parseSeccompMethod(seccompMethod)
	if err != nil {
		fmt.Fprintf(os.Stderr, "amicontained: %v\n", err)
		os.Exit(2)
	}
	switch socketMode = sockets.Mode(*sockMode); socketMode {
	case sockets.ModeScan, sockets.ModeKnown, sockets.ModeNone:
	default:
		fmt.Fprintf(os.Stderr, "amicontained: invalid -sockets %q: want scan, known or none\n", *sockMode)
		os.Exit(2)
	}

	r := gather(method)
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintf(os.Stderr, "amicontained: %v\n", err)
			os.Exit(1)
		}
		return
	}
	printReport(os.Stdout, r)
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, `amicontained:
 version     : %s
 git hash    : %s
 go version  : %s
 go compiler : %s
 platform    : %s/%s
`, version.VERSION, version.GITCOMMIT, runtime.Version(), runtime.Compiler, runtime.GOOS, runtime.GOARCH)
}

func parseSeccompMethod(s string) (seccomp.Method, error) {
	switch s {
	case "auto":
		return seccomp.MethodAuto, nil
	case "notify":
		return seccomp.MethodNotify, nil
	case "heuristic":
		return seccomp.MethodHeuristic, nil
	case "none":
		return seccomp.MethodNone, nil
	}
	return "", fmt.Errorf("invalid -seccomp-method %q: want auto, notify, heuristic or none", s)
}

func gather(method seccomp.Method) *report {
	r := &report{}

	// Seccomp goes first: later checks make real syscalls and ask it which
	// ones are safe.
	opts := seccomp.Options{Method: method}
	if debug {
		opts.Debug = os.Stderr
	}
	r.Seccomp = seccomp.Probe(opts)

	r.Runtime = container.Detect()

	r.Namespaces = procfs.Namespaces()
	r.HostPIDVisible = procfs.HostPIDVisible()
	userNS, mappings := procfs.UserNamespace()
	r.UserMappings = mappings

	status, err := procfs.Status()
	if err == nil {
		if v, ok := status["NoNewPrivs"]; ok {
			nnp := v == "1"
			r.NoNewPrivs = &nnp
		}
		r.Capabilities, err = procfs.ParseCapabilities(status)
	}
	if err != nil {
		r.CapsError = err.Error()
		fmt.Fprintf(os.Stderr, "amicontained: getting capabilities failed: %v\n", err)
	}

	r.LSM = lsm.Detect(r.Seccomp.SafeToCall)

	in := hardening.Inputs{
		SeccompDisabled: r.Seccomp.Mode == seccomp.ModeDisabled,
		LSMConfined:     r.LSM.Confined(),
		UserNamespace:   userNS,
		Sandbox:         r.Runtime.Sandbox,
	}
	if r.Capabilities != nil {
		in.Bounding = r.Capabilities.Bounding.Names
	}
	r.Hardening = hardening.Assess(in)

	sockOpts := sockets.Options{Mode: socketMode, Budget: 5 * time.Second, MaxEntries: 2000000}
	if debug {
		sockOpts.Debug = os.Stderr
	}
	r.Sockets = sockets.Discover(sockOpts)

	return r
}

func printReport(w io.Writer, r *report) {
	printRuntime(w, r.Runtime)

	fmt.Fprintln(w, "Namespaces:")
	for _, ns := range r.Namespaces {
		switch {
		case ns.Error != "":
			fmt.Fprintf(w, "\t%s: error -> %s\n", ns.Type, ns.Error)
		case ns.Host && ns.Exact:
			fmt.Fprintf(w, "\t%s: host\n", ns.Type)
		case ns.Host:
			fmt.Fprintf(w, "\t%s: host (likely)\n", ns.Type)
		case ns.Exact:
			fmt.Fprintf(w, "\t%s: private\n", ns.Type)
		default:
			fmt.Fprintf(w, "\t%s: private (likely)\n", ns.Type)
		}
	}
	if r.HostPIDVisible {
		fmt.Fprintln(w, "\tnote: host processes are visible (kthreadd is PID 2)")
	}
	if len(r.UserMappings) > 0 {
		fmt.Fprintln(w, "User Namespace Mappings:")
		for _, m := range r.UserMappings {
			fmt.Fprintf(w, "\tContainer -> %d\tHost -> %d\tRange -> %d\n", m.ContainerID, m.HostID, m.Range)
		}
	}

	if r.NoNewPrivs != nil {
		fmt.Fprintf(w, "No New Privileges: %t\n", *r.NoNewPrivs)
	}

	printLSM(w, r.LSM)

	if c := r.Capabilities; c != nil {
		fmt.Fprintln(w, "Capabilities:")
		for _, set := range []struct {
			name string
			set  procfs.CapSet
		}{
			{"effective", c.Effective},
			{"permitted", c.Permitted},
			{"inheritable", c.Inheritable},
			{"bounding", c.Bounding},
			{"ambient", c.Ambient},
		} {
			names := strings.Join(set.set.Names, " ")
			if names == "" {
				names = "none"
			}
			fmt.Fprintf(w, "\t%s -> %s\n", set.name, names)
		}
	} else {
		fmt.Fprintf(w, "Capabilities: error -> %s\n", r.CapsError)
	}

	printHardening(w, r.Hardening)

	printSockets(w, r.Sockets)

	printSeccomp(w, r.Seccomp)
}

func printRuntime(w io.Writer, rt *container.Runtime) {
	switch rt.Engine {
	case "":
		fmt.Fprintln(w, "Container Runtime: not found")
	default:
		fmt.Fprintf(w, "Container Runtime: %s\n", rt.Engine)
	}
	if rt.Orchestrator != "" {
		fmt.Fprintf(w, "\torchestrator: %s\n", rt.Orchestrator)
	}
	if rt.Sandbox != "" {
		fmt.Fprintf(w, "\tsandbox: %s\n", rt.Sandbox)
	}
	if rt.ContainerID != "" {
		fmt.Fprintf(w, "\tcontainer id: %s\n", rt.ContainerID)
	}
	if rt.PodUID != "" {
		fmt.Fprintf(w, "\tpod uid: %s\n", rt.PodUID)
	}
	for _, e := range rt.Evidence {
		fmt.Fprintf(w, "\tevidence: %s\n", e)
	}
}

func printLSM(w io.Writer, l *lsm.Report) {
	source := l.Source
	if source == "inferred" {
		source += ", may be incomplete"
	}
	fmt.Fprintf(w, "Security Modules: %s (source: %s)\n", strings.Join(l.Active, ","), source)
	for _, x := range []struct {
		name  string
		label *lsm.Label
	}{{"AppArmor", l.AppArmor}, {"SELinux", l.SELinux}, {"Smack", l.Smack}} {
		if x.label == nil {
			continue
		}
		fmt.Fprintf(w, "\t%s: %s", x.name, x.label.Label)
		switch {
		case !x.label.Confining && x.label.Note != "":
			fmt.Fprintf(w, " (not confining: %s)", x.label.Note)
		case !x.label.Confining:
			fmt.Fprint(w, " (not confining)")
		}
		fmt.Fprintln(w)
	}
	if l.Landlock.Available {
		fmt.Fprintf(w, "\tLandlock: available (ABI %d)\n", l.Landlock.ABI)
	} else {
		fmt.Fprintf(w, "\tLandlock: unavailable (%s)\n", l.Landlock.Error)
	}
}

func printHardening(w io.Writer, h *hardening.Report) {
	p := h.Privileged
	fmt.Fprintf(w, "Privileged Indicators: %d/%d (%s)\n", p.Present, len(p.Indicators), p.Verdict)
	for _, i := range p.Indicators {
		v := "no"
		if i.Present {
			v = "YES"
		}
		if i.Detail != "" && (i.Present || strings.Contains(i.Name, "bounding")) {
			v += " -> " + i.Detail
		}
		fmt.Fprintf(w, "\t%s: %s\n", i.Name, v)
	}

	rootfs := "read-write"
	if h.RootFSReadOnly {
		rootfs = "read-only"
	}
	fmt.Fprintf(w, "Root Filesystem: %s\n", rootfs)

	c := h.Cgroup
	fmt.Fprintf(w, "Cgroup: %s", c.Version)
	if c.Path != "" {
		fmt.Fprintf(w, " (path %s)", c.Path)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "\tmemory limit: %s\n", formatMemory(c.MemoryMax))
	fmt.Fprintf(w, "\tcpu limit: %s\n", formatCPU(c.CPUMax))
	fmt.Fprintf(w, "\tpids limit: %s\n", formatLimit(c.PIDsMax))
}

func formatLimit(v string) string {
	switch v {
	case "":
		return "unknown"
	case "max":
		return "none"
	}
	return v
}

func formatMemory(v string) string {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return formatLimit(v)
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	f, u := float64(n), 0
	for f >= 1024 && u < len(units)-1 {
		f /= 1024
		u++
	}
	return strconv.FormatFloat(f, 'f', -1, 64) + " " + units[u]
}

func formatCPU(v string) string {
	quota, period, ok := strings.Cut(v, " ")
	q, err1 := strconv.ParseFloat(quota, 64)
	p, err2 := strconv.ParseFloat(period, 64)
	if !ok || err1 != nil || err2 != nil || p == 0 {
		return formatLimit(quota)
	}
	return strconv.FormatFloat(q/p, 'f', -1, 64) + " CPUs"
}

func printSockets(w io.Writer, r *sockets.Report) {
	if r.Mode == sockets.ModeNone {
		fmt.Fprintln(w, "Container Sockets: not checked")
		return
	}
	fmt.Fprintln(w, "Container Sockets:")
	if len(r.Sockets) == 0 {
		fmt.Fprintln(w, "\tnone found")
	}
	others := 0
	for _, s := range r.Sockets {
		if !s.Interesting() && !debug {
			others++
			continue
		}
		fmt.Fprintf(w, "\t%s [%s]: ", s.Path, s.Source)
		switch {
		case s.API == "grpc" || s.API == "http":
			what := s.Product
			if what == "" {
				what = "unidentified"
			}
			fmt.Fprintf(w, "%s API (%s)\n", s.API, what)
		case s.Accessible:
			fmt.Fprintf(w, "%s %s", s.Product, s.Version)
			if s.Controls() {
				fmt.Fprint(w, " -> ACCESSIBLE: full control of the engine")
			}
			fmt.Fprintln(w)
		default:
			if s.Guess != "" {
				fmt.Fprintf(w, "%s?, ", s.Guess)
			}
			fmt.Fprintln(w, s.Error)
		}
	}
	if others > 0 {
		fmt.Fprintf(w, "\t(+%d other sockets with no container API; -json or -d lists them)\n", others)
	}
	if sc := r.Scan; sc != nil {
		fmt.Fprintf(w, "\tscan: %d entries in %s", sc.Entries, sc.Duration)
		if sc.Truncated != "" {
			fmt.Fprintf(w, ", incomplete: %s", sc.Truncated)
		}
		fmt.Fprintln(w)
	}
}

func printSeccomp(w io.Writer, s *seccomp.Report) {
	fmt.Fprintf(w, "Seccomp: %s", s.Mode)
	if s.Mode == seccomp.ModeFiltering {
		fmt.Fprintf(w, " (filters: %d, method: %s)", s.Filters, s.Method)
	}
	fmt.Fprintln(w)
	for _, warning := range s.Warnings {
		fmt.Fprintf(w, "\tNote: %s\n", warning)
	}
	if s.DefaultAction != nil {
		fmt.Fprintf(w, "\tDefault action for unknown syscalls: %s\n", describeAction(*s.DefaultAction))
	}
	if s.Method == seccomp.MethodNone {
		return
	}

	blocked := s.Blocked()
	fmt.Fprintf(w, "Blocked Syscalls (%d):\n", len(blocked))
	// Group by how the policy blocks them, in syscall-number order.
	var groups []string
	byGroup := map[string][]string{}
	for _, b := range blocked {
		g := b.Errno
		if b.Action != seccomp.ActionErrno {
			g = string(b.Action)
		}
		if _, ok := byGroup[g]; !ok {
			groups = append(groups, g)
		}
		byGroup[g] = append(byGroup[g], b.Syscall)
	}
	for _, g := range groups {
		fmt.Fprintf(w, "\t%s (%d): %s\n", g, len(byGroup[g]), strings.Join(byGroup[g], " "))
	}

	if len(s.ArgumentChecks) > 0 {
		fmt.Fprintln(w, "Argument Checks:")
		for _, a := range s.ArgumentChecks {
			fmt.Fprintf(w, "\t%s: %s\n", a.Args, describeAction(a))
		}
	}

	var other []string
	for _, r := range s.Syscalls {
		if r.Action == seccomp.ActionUnknown || r.Action == seccomp.ActionSkipped {
			other = append(other, fmt.Sprintf("%s (%s)", r.Syscall, r.Action))
		}
	}
	if len(other) > 0 {
		fmt.Fprintf(w, "Undetermined Syscalls (%d):\n\t%s\n", len(other), strings.Join(other, " "))
	}

	if debug {
		var allowed []string
		for _, r := range s.Syscalls {
			if r.Action == seccomp.ActionAllow {
				allowed = append(allowed, r.Syscall)
			}
		}
		fmt.Fprintf(w, "Allowed Syscalls (%d):\n\t%s\n", len(allowed), strings.Join(allowed, " "))
	}
}

func describeAction(r seccomp.Result) string {
	switch r.Action {
	case seccomp.ActionAllow:
		return "allowed"
	case seccomp.ActionErrno:
		return "blocked (" + r.Errno + ")"
	case seccomp.ActionKill, seccomp.ActionTrap:
		return "blocked (" + string(r.Action) + ")"
	}
	if r.Detail != "" {
		return string(r.Action) + " (" + r.Detail + ")"
	}
	return string(r.Action)
}
