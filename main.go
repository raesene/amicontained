package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/genuinetools/amicontained/internal/container"
	"github.com/genuinetools/amicontained/internal/procfs"
	"github.com/genuinetools/amicontained/internal/seccomp"
	"github.com/genuinetools/amicontained/version"
)

var (
	debug         bool
	jsonOutput    bool
	seccompMethod string
)

// report is everything amicontained found, in output order.
type report struct {
	Runtime      *container.Runtime   `json:"runtime"`
	Namespaces   namespaces           `json:"namespaces"`
	AppArmor     string               `json:"apparmor_profile"`
	Capabilities *procfs.Capabilities `json:"capabilities"`
	CapsError    string               `json:"capabilities_error,omitempty"`
	DockerSocks  []string             `json:"docker_sockets"`
	Seccomp      *seccomp.Report      `json:"seccomp"`
}

type namespaces struct {
	PID          *bool                `json:"pid,omitempty"`
	PIDError     string               `json:"pid_error,omitempty"`
	User         bool                 `json:"user"`
	UserMappings []procfs.UserMapping `json:"user_mappings,omitempty"`
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

	// Container Runtime
	r.Runtime = container.Detect()

	// Namespaces
	if ns, err := procfs.HasNamespace("pid"); err != nil {
		r.Namespaces.PIDError = err.Error()
	} else {
		r.Namespaces.PID = &ns
	}
	r.Namespaces.User, r.Namespaces.UserMappings = procfs.UserNamespace()

	// AppArmor Profile
	r.AppArmor = procfs.AppArmorProfile()

	// Capabilities
	status, err := procfs.Status()
	if err == nil {
		r.Capabilities, err = procfs.ParseCapabilities(status)
	}
	if err != nil {
		r.CapsError = err.Error()
		fmt.Fprintf(os.Stderr, "amicontained: getting capabilities failed: %v\n", err)
	}

	// Docker.sock
	r.DockerSocks = getValidSockets("/")

	// Seccomp
	opts := seccomp.Options{Method: method}
	if debug {
		opts.Debug = os.Stderr
	}
	r.Seccomp = seccomp.Probe(opts)

	return r
}

func printReport(w io.Writer, r *report) {
	printRuntime(w, r.Runtime)

	fmt.Fprintln(w, "Has Namespaces:")
	if r.Namespaces.PID != nil {
		fmt.Fprintf(w, "\tpid: %t\n", *r.Namespaces.PID)
	} else {
		fmt.Fprintf(w, "\tpid: error -> %s\n", r.Namespaces.PIDError)
	}
	fmt.Fprintf(w, "\tuser: %t\n", r.Namespaces.User)
	if len(r.Namespaces.UserMappings) > 0 {
		fmt.Fprintln(w, "User Namespace Mappings:")
		for _, m := range r.Namespaces.UserMappings {
			fmt.Fprintf(w, "\tContainer -> %d\tHost -> %d\tRange -> %d\n", m.ContainerID, m.HostID, m.Range)
		}
	}

	fmt.Fprintf(w, "AppArmor Profile: %s\n", r.AppArmor)

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

	fmt.Fprintln(w, "Docker Sockets:")
	if len(r.DockerSocks) == 0 {
		fmt.Fprintln(w, "\tnone found")
	}
	for _, s := range r.DockerSocks {
		fmt.Fprintf(w, "\t%s\n", s)
	}

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

func getValidSockets(startPath string) []string {
	var found []string
	err := filepath.Walk(startPath, func(path string, info os.FileInfo, err error) error {
		if debug {
			fmt.Fprintln(os.Stderr, "Checking path: "+path)
		}
		if err != nil {
			if debug {
				fmt.Fprintln(os.Stderr, err)
			}
			return nil
		}
		if info.Mode()&os.ModeSocket == 0 {
			return nil
		}
		if debug {
			fmt.Fprintln(os.Stderr, "Valid Socket: "+path)
		}
		resp, err := checkSock(path)
		if err != nil {
			if debug {
				fmt.Fprintln(os.Stderr, "Invalid Docker Socket: "+path)
			}
			return nil
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			found = append(found, path)
		} else if debug {
			fmt.Fprintln(os.Stderr, "Invalid Docker Socket: "+path)
		}
		return nil
	})
	if err != nil && debug {
		fmt.Fprintln(os.Stderr, err)
	}
	return found
}

func checkSock(path string) (*http.Response, error) {
	if debug {
		fmt.Fprintln(os.Stderr, "[-] Checking Sock for HTTP: "+path)
	}
	dialer := net.Dialer{Timeout: 100 * time.Millisecond}
	client := http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", path)
			},
			ResponseHeaderTimeout: time.Second,
			DisableKeepAlives:     true,
		},
	}
	return client.Get("http://docker/info")
}
