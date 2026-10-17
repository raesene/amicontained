package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/genuinetools/amicontained/internal/container"
	"github.com/genuinetools/amicontained/internal/hardening"
	"github.com/genuinetools/amicontained/internal/lsm"
	"github.com/genuinetools/amicontained/internal/procfs"
	"github.com/genuinetools/amicontained/internal/report"
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

func main() {
	// A re-executed copy of ourselves probing the seccomp policy.
	if seccomp.IsChild() {
		seccomp.RunChild()
		return
	}

	fs := flag.NewFlagSet("amicontained", flag.ExitOnError)
	fs.BoolVar(&debug, "d", false, "enable debug logging on stderr")
	fs.BoolVar(&jsonOutput, "json", false, "output results as JSON")
	verbose := fs.Bool("v", false, "show full details instead of summaries")
	noColor := fs.Bool("no-color", false, "disable colour (also off when NO_COLOR is set or output is not a terminal)")
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
	r.WriteText(os.Stdout, report.TextOptions{
		Color:   !*noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout),
		Verbose: *verbose,
	})
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
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

func gather(method seccomp.Method) *report.Report {
	r := &report.Report{Version: version.VERSION}

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
	r.UserNamespace, r.UserMappings = procfs.UserNamespace()

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
		UserNamespace:   r.UserNamespace,
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

	r.ComputeFindings()
	return r
}
