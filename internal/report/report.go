// Package report holds everything amicontained found, derives the findings
// summary from it, and renders it as text.
package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/genuinetools/amicontained/internal/container"
	"github.com/genuinetools/amicontained/internal/hardening"
	"github.com/genuinetools/amicontained/internal/lsm"
	"github.com/genuinetools/amicontained/internal/procfs"
	"github.com/genuinetools/amicontained/internal/seccomp"
	"github.com/genuinetools/amicontained/internal/sockets"
)

// Report is everything amicontained found.
type Report struct {
	Version        string               `json:"version"`
	Findings       []Finding            `json:"findings"`
	Runtime        *container.Runtime   `json:"runtime"`
	Namespaces     []procfs.Namespace   `json:"namespaces"`
	HostPIDVisible bool                 `json:"host_pid_visible"`
	UserNamespace  bool                 `json:"user_namespace"`
	UserMappings   []procfs.UserMapping `json:"user_mappings,omitempty"`
	NoNewPrivs     *bool                `json:"no_new_privs"`
	LSM            *lsm.Report          `json:"lsm"`
	Capabilities   *procfs.Capabilities `json:"capabilities"`
	CapsError      string               `json:"capabilities_error,omitempty"`
	Hardening      *hardening.Report    `json:"hardening"`
	Sockets        *sockets.Report      `json:"sockets"`
	Seccomp        *seccomp.Report      `json:"seccomp"`
}

// Severity ranks a finding.
type Severity string

const (
	High   Severity = "high"   // isolation is effectively broken
	Medium Severity = "medium" // isolation is weakened
	Info   Severity = "info"   // context needed to read the rest correctly
)

// Finding is one way the environment differs from a default, isolated
// container.
type Finding struct {
	Severity Severity `json:"severity"`
	Summary  string   `json:"summary"`
	Detail   string   `json:"detail,omitempty"`
}

// dangerousCaps are capabilities that container runtimes leave out by
// default because each enables a known escape or host-impact technique.
var dangerousCaps = []string{
	"sys_admin", "sys_module", "sys_ptrace", "sys_rawio", "dac_read_search", "sys_boot",
	"sys_time", "net_admin", "bpf", "perfmon", "syslog", "mac_admin", "mac_override",
	"linux_immutable", "sys_resource",
}

// hostNamespaceImpact says what sharing each namespace with the host gives
// away. user and time are shared by default by every mainstream runtime.
var hostNamespaceImpact = map[string]struct {
	severity Severity
	impact   string
}{
	"pid":    {High, "host processes are visible and may be signalled or traced"},
	"net":    {High, "host network interfaces and localhost services are reachable"},
	"mnt":    {High, "the host's mount table is in use"},
	"ipc":    {Medium, "host shared memory and message queues are reachable"},
	"uts":    {Medium, "the host's hostname can be changed"},
	"cgroup": {Medium, "the host's cgroup hierarchy is visible"},
}

// ComputeFindings fills in r.Findings, most severe first.
func (r *Report) ComputeFindings() {
	var high, medium, info []Finding
	add := func(s Severity, summary, detail string) {
		f := Finding{Severity: s, Summary: summary, Detail: detail}
		switch s {
		case High:
			high = append(high, f)
		case Medium:
			medium = append(medium, f)
		default:
			info = append(info, f)
		}
	}

	if rt := r.Runtime; rt != nil {
		if rt.Engine == "" && r.hostNamespace("pid") && r.hostNamespace("mnt") {
			add(Info, "no container detected; this looks like the host itself", "")
		}
		if rt.Sandbox != "" {
			add(Info, "running in a "+rt.Sandbox+" sandbox",
				"kernel-level results (namespaces, capabilities, seccomp, privileged indicators) describe the sandbox's own kernel, not the host")
		}
		if rt.ServiceAccountToken {
			add(Medium, "Kubernetes service account token is mounted",
				"/var/run/secrets/kubernetes.io/serviceaccount/token gives API credentials to anything in the container")
		}
	}

	if r.Sockets != nil {
		for _, s := range r.Sockets.Sockets {
			switch {
			case s.Controls():
				add(High, s.Path+": "+s.Product+" API is accessible",
					"full control of the container engine, which usually means root on the host")
			case s.Accessible && s.API == "grpc" && strings.HasPrefix(s.Guess, "kubelet"):
				add(Medium, s.Path+": "+s.Guess+" API is reachable", "")
			}
		}
	}

	// Privileged indicators. When most are present, report them as one.
	collapsed := false
	if h := r.Hardening; h != nil {
		p := h.Privileged
		var present []string
		for _, i := range p.Indicators {
			if i.Present {
				present = append(present, i.Name)
			}
		}
		if p.Verdict != "" && strings.HasPrefix(p.Verdict, "looks privileged") {
			collapsed = true
			detail := strings.Join(present, ", ")
			if r.UserNamespace {
				detail += "; in a user namespace, so capabilities apply only within it"
			}
			if sb := sandbox(r.Runtime); sb != "" {
				// The indicators describe the sandbox's emulated kernel.
				add(Info, fmt.Sprintf("privileged inside the %s sandbox (%d/%d indicators)", sb, p.Present, len(p.Indicators)), detail)
			} else {
				add(High, fmt.Sprintf("looks like a privileged container (%d/%d indicators)", p.Present, len(p.Indicators)), detail)
			}
		} else {
			for _, i := range p.Indicators {
				if !i.Present || i.Name == "seccomp disabled" || i.Name == "no LSM confinement" {
					continue
				}
				add(Medium, i.Name, i.Detail)
			}
		}
		if !collapsed && r.Seccomp != nil && r.Seccomp.Mode == seccomp.ModeDisabled {
			add(High, "seccomp is disabled", "every syscall is available to the container")
		}
		if !collapsed && r.LSM != nil && !r.LSM.Confined() {
			add(Medium, "no LSM confinement", "neither AppArmor, SELinux nor Smack restricts this process")
		}
	}

	if r.Runtime == nil || r.Runtime.Engine != "" {
		for _, ns := range r.Namespaces {
			if impact, ok := hostNamespaceImpact[ns.Type]; ok && ns.Host {
				summary := "shares the host " + ns.Type + " namespace"
				if !ns.Exact {
					summary += " (likely)"
				}
				add(impact.severity, summary, impact.impact)
			}
		}
	}

	if c := r.Capabilities; c != nil && !collapsed {
		var found []string
		for _, cp := range dangerousCaps {
			if slices.Contains(c.Bounding.Names, cp) {
				found = append(found, cp)
			}
		}
		if len(found) > 0 {
			detail := "in the bounding set"
			if r.UserNamespace {
				detail += "; in a user namespace, so they apply only within it"
			}
			add(Medium, "dangerous capabilities: "+strings.Join(found, " "), detail)
		}
	}

	if s := r.Seccomp; s != nil && s.Mode == seccomp.ModeFiltering {
		if s.Method == seccomp.MethodHeuristic {
			add(Info, "seccomp results are heuristic", "the notify probe was unavailable, so syscalls were executed and errors may come from other layers")
		}
		for _, call := range []string{"unshare(CLONE_NEWUSER)", "clone(CLONE_NEWUSER)"} {
			if a, ok := s.ArgumentCheck(call); ok && a.Action == seccomp.ActionAllow {
				add(Medium, "seccomp allows creating user namespaces",
					call+" is allowed; unprivileged user namespaces expose kernel code normally reserved for root")
				break
			}
		}
	}

	r.Findings = slices.Concat(high, medium, info)
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
}

func sandbox(rt *container.Runtime) string {
	if rt == nil {
		return ""
	}
	return rt.Sandbox
}

func (r *Report) hostNamespace(t string) bool {
	for _, ns := range r.Namespaces {
		if ns.Type == t {
			return ns.Host
		}
	}
	return false
}
