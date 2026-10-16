package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/genuinetools/amicontained/internal/seccomp"
	"github.com/genuinetools/amicontained/version"
	"github.com/genuinetools/pkg/cli"
	"github.com/jessfraz/bpfd/proc"
	"github.com/sirupsen/logrus"
	"github.com/tv42/httpunix"
)

var (
	debug         bool
	jsonOutput    bool
	seccompMethod string
)

// report is everything amicontained found, in output order.
type report struct {
	Runtime      string              `json:"runtime"`
	Namespaces   namespaces          `json:"namespaces"`
	AppArmor     string              `json:"apparmor_profile"`
	Capabilities map[string][]string `json:"capabilities"`
	DockerSocks  []string            `json:"docker_sockets"`
	Seccomp      *seccomp.Report     `json:"seccomp"`
}

type namespaces struct {
	PID          *bool              `json:"pid,omitempty"`
	PIDError     string             `json:"pid_error,omitempty"`
	User         bool               `json:"user"`
	UserMappings []proc.UserMapping `json:"user_mappings,omitempty"`
}

func main() {
	// A re-executed copy of ourselves probing the seccomp policy.
	if seccomp.IsChild() {
		seccomp.RunChild()
		return
	}

	// Create a new cli program.
	p := cli.NewProgram()
	p.Name = "amicontained"
	p.Description = "A container introspection tool"

	// Set the GitCommit and Version.
	p.GitCommit = version.GITCOMMIT
	p.Version = version.VERSION

	// Setup the global flags.
	p.FlagSet = flag.NewFlagSet("amicontained", flag.ExitOnError)
	p.FlagSet.BoolVar(&debug, "d", false, "enable debug logging")
	p.FlagSet.BoolVar(&jsonOutput, "json", false, "output results as JSON")
	p.FlagSet.StringVar(&seccompMethod, "seccomp-method", "auto", "seccomp probing method: auto, notify, heuristic or none")

	// Set the before function.
	p.Before = func(ctx context.Context) error {
		// Set the log level.
		if debug {
			logrus.SetLevel(logrus.DebugLevel)
		}

		return nil
	}

	// Set the main program action.
	p.Action = func(ctx context.Context, args []string) error {
		method, err := parseSeccompMethod(seccompMethod)
		if err != nil {
			return err
		}

		r := gather(method)
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(r)
		}
		printReport(os.Stdout, r)
		return nil
	}

	// Run our program.
	p.Run()
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
	r.Runtime = string(proc.GetContainerRuntime(0, 0))

	// Namespaces
	if ns, err := proc.HasNamespace("pid"); err != nil {
		r.Namespaces.PIDError = err.Error()
	} else {
		r.Namespaces.PID = &ns
	}
	r.Namespaces.User, r.Namespaces.UserMappings = proc.GetUserNamespaceInfo(0)

	// AppArmor Profile
	r.AppArmor = proc.GetAppArmorProfile(0)

	// Capabilities
	caps, err := proc.GetCapabilities(0)
	if err != nil {
		logrus.Warnf("getting capabilities failed: %v", err)
	}
	r.Capabilities = caps

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
	fmt.Fprintf(w, "Container Runtime: %s\n", r.Runtime)

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

	if len(r.Capabilities) > 0 {
		fmt.Fprintln(w, "Capabilities:")
		sets := make([]string, 0, len(r.Capabilities))
		for k := range r.Capabilities {
			sets = append(sets, k)
		}
		sort.Strings(sets)
		for _, k := range sets {
			if v := r.Capabilities[k]; len(v) > 0 {
				fmt.Fprintf(w, "\t%s -> %s\n", k, strings.Join(v, " "))
			}
		}
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
	u := &httpunix.Transport{
		DialTimeout:           100 * time.Millisecond,
		RequestTimeout:        1 * time.Second,
		ResponseHeaderTimeout: 1 * time.Second,
	}
	u.RegisterLocation("dockerd", path)
	var client = http.Client{
		Transport: u,
	}
	return client.Get("http+unix://dockerd/info")
}
