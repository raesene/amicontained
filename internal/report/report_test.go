package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/genuinetools/amicontained/internal/container"
	"github.com/genuinetools/amicontained/internal/hardening"
	"github.com/genuinetools/amicontained/internal/lsm"
	"github.com/genuinetools/amicontained/internal/procfs"
	"github.com/genuinetools/amicontained/internal/seccomp"
	"github.com/genuinetools/amicontained/internal/sockets"
)

var defaultCaps = strings.Fields("chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap")

func capSet(names []string) procfs.CapSet {
	return procfs.CapSet{Hex: "00000000a80425fb", Names: names}
}

func namespaces(host ...string) []procfs.Namespace {
	var out []procfs.Namespace
	for _, t := range procfs.NamespaceTypes {
		ns := procfs.Namespace{Type: t, Exact: true}
		for _, h := range append([]string{"user", "time"}, host...) {
			if h == t {
				ns.Host = true
			}
		}
		out = append(out, ns)
	}
	return out
}

func indicators(present ...string) hardening.Privileged {
	names := []string{"host devices in /dev", "/sys mounted read-write", "/proc/sys mounted read-write",
		"masked paths exposed", "all capabilities in bounding set", "seccomp disabled", "no LSM confinement"}
	p := hardening.Privileged{Verdict: "none present"}
	for _, n := range names {
		i := hardening.Indicator{Name: n}
		for _, x := range present {
			if x == n {
				i.Present = true
				p.Present++
			}
		}
		p.Indicators = append(p.Indicators, i)
	}
	switch {
	case p.Present >= 5:
		p.Verdict = "looks privileged"
	case p.Present > 0:
		p.Verdict = "some present"
	}
	return p
}

// dockerDefault is a default Docker container as measured on the test server.
func dockerDefault() *Report {
	nnp := false
	return &Report{
		Version: "v0.4.9",
		Runtime: &container.Runtime{Engine: "docker", ContainerID: strings.Repeat("8d8ed6d4eb6d", 6)[:64],
			Evidence: []string{"/.dockerenv exists", "mountinfo: /etc/hosts from /var/lib/docker/containers/"}},
		Namespaces: namespaces(),
		NoNewPrivs: &nnp,
		LSM: &lsm.Report{Active: []string{"capability", "apparmor", "yama", "landlock"}, Source: "inferred",
			AppArmor: &lsm.Label{Label: "docker-default (enforce)", Confining: true},
			Landlock: lsm.Landlock{Available: true, ABI: 8}},
		Capabilities: &procfs.Capabilities{Effective: capSet(defaultCaps), Permitted: capSet(defaultCaps),
			Bounding: capSet(defaultCaps), Inheritable: procfs.CapSet{Hex: "0"}, Ambient: procfs.CapSet{Hex: "0"}},
		Hardening: &hardening.Report{Privileged: indicators(),
			Cgroup: hardening.Cgroup{Version: "v2", Path: "/", MemoryMax: "max", CPUMax: "max 100000", PIDsMax: "70360"}},
		Sockets: &sockets.Report{Mode: sockets.ModeScan, Sockets: []sockets.Socket{}, Scan: &sockets.ScanInfo{Entries: 535, Duration: "2ms"}},
		Seccomp: &seccomp.Report{Mode: seccomp.ModeFiltering, Filters: 1, Method: seccomp.MethodNotify,
			Syscalls: []seccomp.Result{
				{Syscall: "read", Action: seccomp.ActionAllow},
				{Syscall: "mount", Action: seccomp.ActionErrno, Errno: "EPERM"},
				{Syscall: "clone3", Action: seccomp.ActionErrno, Errno: "ENOSYS"},
			},
			ArgumentChecks: []seccomp.Result{
				{Syscall: "unshare", Args: "unshare(CLONE_NEWUSER) - create a user namespace", Action: seccomp.ActionErrno, Errno: "EPERM"},
			}},
	}
}

func summaries(r *Report) []string {
	r.ComputeFindings()
	var s []string
	for _, f := range r.Findings {
		s = append(s, string(f.Severity)+": "+f.Summary)
	}
	return s
}

func TestFindings(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Report)
		want   []string
	}{
		{"docker default", func(*Report) {}, nil},
		{
			"docker socket mounted",
			func(r *Report) {
				r.Sockets.Sockets = []sockets.Socket{
					{Path: "/run/docker.sock", API: "docker", Product: "Docker Engine", Accessible: true},
					{Path: "/run/user/1000/bus", Source: "scan", Error: "connected, but no known API answered"},
				}
			},
			[]string{"high: /run/docker.sock: Docker Engine API is accessible"},
		},
		{
			"privileged",
			func(r *Report) {
				r.Hardening.Privileged = indicators("host devices in /dev", "/sys mounted read-write", "/proc/sys mounted read-write",
					"masked paths exposed", "all capabilities in bounding set", "seccomp disabled", "no LSM confinement")
				r.Seccomp = &seccomp.Report{Mode: seccomp.ModeDisabled, Method: seccomp.MethodNone}
				r.LSM.AppArmor = &lsm.Label{Label: "unconfined"}
				r.Capabilities.Bounding = capSet(append(defaultCaps, "sys_admin", "sys_module"))
			},
			// One collapsed finding instead of nine overlapping ones.
			[]string{"high: looks like a privileged container (7/7 indicators)"},
		},
		{
			"host namespaces",
			func(r *Report) { r.Namespaces = namespaces("pid", "net", "ipc", "uts", "cgroup") },
			[]string{"high: shares the host net namespace", "high: shares the host pid namespace",
				"medium: shares the host cgroup namespace", "medium: shares the host ipc namespace", "medium: shares the host uts namespace"},
		},
		{
			"seccomp unconfined, cap-add SYS_ADMIN",
			func(r *Report) {
				r.Seccomp = &seccomp.Report{Mode: seccomp.ModeDisabled, Method: seccomp.MethodNone}
				r.Hardening.Privileged = indicators("seccomp disabled")
				r.Capabilities.Bounding = capSet(append(defaultCaps, "sys_admin"))
			},
			[]string{"high: seccomp is disabled", "medium: dangerous capabilities: sys_admin"},
		},
		{
			"kubernetes pod with token, user namespaces allowed",
			func(r *Report) {
				r.Runtime = &container.Runtime{Engine: "containerd", Orchestrator: "kubernetes", ServiceAccountToken: true}
				r.Seccomp.ArgumentChecks[0].Action = seccomp.ActionAllow
				r.Sockets.Sockets = []sockets.Socket{{Path: "/var/lib/kubelet/pod-resources/kubelet.sock", Guess: "kubelet pod-resources", API: "grpc", Accessible: true}}
			},
			[]string{"medium: Kubernetes service account token is mounted",
				"medium: /var/lib/kubelet/pod-resources/kubelet.sock: kubelet pod-resources API is reachable",
				"medium: seccomp allows creating user namespaces"},
		},
		{
			"gvisor",
			func(r *Report) {
				r.Runtime = &container.Runtime{Engine: "unknown", Sandbox: "gvisor"}
				r.Hardening.Privileged = indicators("host devices in /dev", "/sys mounted read-write", "/proc/sys mounted read-write",
					"masked paths exposed", "seccomp disabled", "no LSM confinement")
				r.Seccomp = &seccomp.Report{Mode: seccomp.ModeDisabled}
			},
			[]string{"info: running in a gvisor sandbox", "info: privileged inside the gvisor sandbox (6/7 indicators)"},
		},
		{
			"rootless podman --privileged",
			func(r *Report) {
				r.UserNamespace = true
				r.Hardening.Privileged = indicators("/sys mounted read-write", "/proc/sys mounted read-write",
					"masked paths exposed", "all capabilities in bounding set", "seccomp disabled", "no LSM confinement")
			},
			[]string{"high: looks like a privileged container (6/7 indicators)"},
		},
		{
			"the host itself",
			func(r *Report) {
				r.Runtime = &container.Runtime{}
				r.Namespaces = namespaces("pid", "net", "mnt", "ipc", "uts", "cgroup")
			},
			[]string{"info: no container detected; this looks like the host itself"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := dockerDefault()
			tt.modify(r)
			got := summaries(r)
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("findings:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(tt.want, "\n  "))
			}
		})
	}
}

func TestWriteText(t *testing.T) {
	r := dockerDefault()
	r.ComputeFindings()
	var b bytes.Buffer
	r.WriteText(&b, TextOptions{})
	out := b.String()

	if strings.Contains(out, "\x1b[") {
		t.Error("colour codes without Color")
	}
	order := []string{"amicontained v0.4.9 - docker container 8d8ed6d4eb6d", "FINDINGS", "none: this looks like a default",
		"RUNTIME", "ISOLATION", "PRIVILEGES", "SECURITY MODULES", "SOCKETS", "SECCOMP  filtering"}
	pos := 0
	for _, s := range order {
		i := strings.Index(out[pos:], s)
		if i < 0 {
			t.Fatalf("missing or out of order: %q\n%s", s, out)
		}
		pos += i
	}
	for _, s := range []string{
		"capabilities  effective = permitted = bounding (14)",
		"inheritable = ambient: none",
		"private: cgroup ipc mnt net pid uts",
		"host:    time user",
		"(+1 more, -v)",
		"v2; memory none, cpu none, pids 70360",
		"EPERM (1)",
		"unshare(CLONE_NEWUSER)",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q\n%s", s, out)
		}
	}
	r.Hardening.Privileged = indicators("host devices in /dev", "/sys mounted read-write", "/proc/sys mounted read-write",
		"masked paths exposed", "all capabilities in bounding set", "seccomp disabled", "no LSM confinement")
	r.UserNamespace = true
	r.ComputeFindings()
	b.Reset()
	r.WriteText(&b, TextOptions{})
	out = b.String()
	if !strings.Contains(out, "in a user namespace") {
		t.Errorf("user namespace caveat missing\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) > lineWidth+20 {
			t.Errorf("overlong line (%d): %q", len(line), line)
		}
	}

	b.Reset()
	r.WriteText(&b, TextOptions{Color: true, Verbose: true})
	out = b.String()
	if !strings.Contains(out, "\x1b[1mFINDINGS") {
		t.Error("no colour with Color")
	}
	for _, s := range []string{"8d8ed6d4eb6d8d8ed6d4eb6d", "mountinfo: /etc/hosts", "allowed (1)", "scan: 535 entries"} {
		if !strings.Contains(out, s) {
			t.Errorf("verbose output missing %q", s)
		}
	}
}

func TestFormat(t *testing.T) {
	for in, want := range map[string]string{"268435456": "256 MiB", "max": "none", "": "unknown"} {
		if got := formatMemory(in); got != want {
			t.Errorf("formatMemory(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"150000 100000": "1.5 CPUs", "max 100000": "none"} {
		if got := formatCPU(in); got != want {
			t.Errorf("formatCPU(%q) = %q, want %q", in, got, want)
		}
	}
}
