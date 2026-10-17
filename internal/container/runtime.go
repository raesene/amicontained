// Package container works out which container engine, orchestrator and
// sandbox we are running under, and records the evidence for each answer.
package container

import (
	"bytes"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

// Runtime is what Detect found. Engine is empty when nothing points to a
// container, and "unknown" when something does but not to a specific engine.
type Runtime struct {
	Engine       string   `json:"engine"`
	Orchestrator string   `json:"orchestrator,omitempty"`
	Sandbox      string   `json:"sandbox,omitempty"`
	ContainerID  string   `json:"container_id,omitempty"`
	PodUID       string   `json:"pod_uid,omitempty"`
	Evidence     []string `json:"evidence"`
}

// Detect inspects the running system.
func Detect() *Runtime {
	return detect(os.DirFS("/"), os.Getenv)
}

// detector accumulates signals. The first engine reported wins, so checks
// run strongest first.
type detector struct {
	fsys fs.FS
	r    Runtime
}

func (d *detector) engine(name, id, evidence string) {
	if d.r.Engine == "" {
		d.r.Engine = name
	}
	if d.r.ContainerID == "" && id != "" && name == d.r.Engine {
		d.r.ContainerID = id
	}
	d.evidence(evidence)
}

func (d *detector) evidence(e string) {
	for _, have := range d.r.Evidence {
		if have == e {
			return
		}
	}
	d.r.Evidence = append(d.r.Evidence, e)
}

func (d *detector) exists(name string) bool {
	_, err := fs.Stat(d.fsys, name)
	return err == nil
}

func (d *detector) read(name string) string {
	b, _ := fs.ReadFile(d.fsys, name)
	return string(b)
}

func detect(fsys fs.FS, getenv func(string) string) *Runtime {
	d := &detector{fsys: fsys}
	d.r.Evidence = []string{}

	if v := d.read("proc/version"); strings.Contains(v, "gvisor") {
		d.r.Sandbox = "gvisor"
		d.evidence("/proc/version: " + strings.TrimSpace(v))
	}

	// Kubernetes is checked before the engine so that CRI-O and podman,
	// which share container storage paths, can be told apart.
	if getenv("KUBERNETES_SERVICE_HOST") != "" {
		d.r.Orchestrator = "kubernetes"
		d.evidence("KUBERNETES_SERVICE_HOST is set")
	}
	if d.exists("var/run/secrets/kubernetes.io/serviceaccount") {
		d.r.Orchestrator = "kubernetes"
		d.evidence("/var/run/secrets/kubernetes.io/serviceaccount exists")
	}
	mounts := mountRoots(d.read("proc/self/mountinfo"))
	for _, m := range mounts {
		if uid := kubeletPodRe.FindStringSubmatch(m.root); uid != nil {
			d.r.Orchestrator = "kubernetes"
			d.r.PodUID = uid[1]
			d.evidence("mountinfo: " + m.point + " from kubelet pod " + uid[1])
			break
		}
	}

	if d.exists(".dockerenv") {
		d.engine("docker", "", "/.dockerenv exists")
	}
	if d.exists("run/.containerenv") {
		d.containerenv(d.read("run/.containerenv"))
	}
	d.mountinfo(mounts)
	d.cgroup(d.read("proc/self/cgroup"))

	// systemd's convention for telling PID 1 it is in a container.
	if v := getenv("container"); v != "" {
		d.containerVar(v, "$container")
	}
	if v := envVar(d.read("proc/1/environ"), "container"); v != "" {
		d.containerVar(v, "/proc/1/environ container")
	}
	if v := strings.TrimSpace(d.read("run/systemd/container")); v != "" {
		d.containerVar(v, "/run/systemd/container")
	}

	// /proc/vz exists inside and outside an OpenVZ container, /proc/bc only
	// outside.
	if d.exists("proc/vz") && !d.exists("proc/bc") {
		d.engine("openvz", "", "/proc/vz exists without /proc/bc")
	}

	if d.r.Engine == "" && (d.r.Orchestrator != "" || d.r.Sandbox != "") {
		d.r.Engine = "unknown"
	}
	return &d.r
}

// containerenv handles podman's /run/.containerenv, which holds key="value"
// lines such as engine="podman-5.0.0" and id="<64 hex>" (empty in rootless
// or when --privileged is not set on older versions).
func (d *detector) containerenv(s string) {
	engine := "podman"
	if d.r.Orchestrator == "kubernetes" {
		engine = "cri-o"
	}
	vals := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			vals[k] = strings.Trim(v, `"`)
		}
	}
	if e := vals["engine"]; e != "" {
		engine, _, _ = strings.Cut(e, "-")
	}
	d.engine(engine, vals["id"], "/run/.containerenv exists")
}

var (
	kubeletPodRe   = regexp.MustCompile(`/kubelet/pods/([0-9a-f-]{36})/`)
	dockerMountRe  = regexp.MustCompile(`/docker/containers/([0-9a-f]{64})/`)
	storageMountRe = regexp.MustCompile(`/containers/storage/[^/]+-containers/([0-9a-f]{64})/userdata/`)
	criSandboxRe   = regexp.MustCompile(`/io\.containerd\.grpc\.v1\.cri/sandboxes/([0-9a-f]{64})/`)
)

type mount struct {
	root, point, fstype, superOpts string
}

// mountRoots parses /proc/self/mountinfo. The root field is the path inside
// the source filesystem, which for bind mounts leaks host paths such as
// /var/lib/docker/containers/<id>/hostname.
func mountRoots(s string) []mount {
	var out []mount
	for _, line := range strings.Split(s, "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		f, g := strings.Fields(pre), strings.Fields(post)
		if len(f) < 5 || len(g) < 3 {
			continue
		}
		out = append(out, mount{root: f[3], point: f[4], fstype: g[0], superOpts: g[2]})
	}
	return out
}

func (d *detector) mountinfo(mounts []mount) {
	for _, m := range mounts {
		if id := dockerMountRe.FindStringSubmatch(m.root); id != nil {
			d.engine("docker", id[1], "mountinfo: "+m.point+" from /var/lib/docker/containers/")
		}
	}
	for _, m := range mounts {
		if id := storageMountRe.FindStringSubmatch(m.root); id != nil {
			engine := "podman"
			if d.r.Orchestrator == "kubernetes" {
				engine = "cri-o"
			}
			d.engine(engine, id[1], "mountinfo: "+m.point+" from containers/storage")
		}
	}
	for _, m := range mounts {
		if id := criSandboxRe.FindStringSubmatch(m.root); id != nil {
			d.engine("containerd", "", "mountinfo: "+m.point+" from containerd CRI sandbox "+id[1][:12])
		}
	}
	for _, m := range mounts {
		if m.point == "/" && m.fstype == "overlay" && strings.Contains(m.superOpts, "/io.containerd.snapshotter.v1.") {
			d.engine("containerd", "", "mountinfo: / is a containerd snapshot")
		}
	}
}

var cgroupPatterns = []struct {
	re     *regexp.Regexp
	engine string
}{
	{regexp.MustCompile(`/docker[-/]([0-9a-f]{64})(?:\.scope)?$`), "docker"},
	{regexp.MustCompile(`/libpod-([0-9a-f]{64})(?:\.scope)?$`), "podman"},
	{regexp.MustCompile(`/crio-([0-9a-f]{64})(?:\.scope)?$`), "cri-o"},
	{regexp.MustCompile(`/cri-containerd-([0-9a-f]{64})(?:\.scope)?$`), "containerd"},
	{regexp.MustCompile(`/lxc(?:\.payload\.|/)([^/]+)`), "lxc"},
	{regexp.MustCompile(`/garden/([^/]+)`), "garden"},
}

// cgroup checks /proc/self/cgroup. With a private cgroup namespace (the
// default on cgroup v2) this is just "0::/" and tells us nothing.
func (d *detector) cgroup(s string) {
	for _, line := range strings.Split(s, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		if strings.Contains(path, "kubepods") {
			d.r.Orchestrator = "kubernetes"
			d.evidence("cgroup: " + path)
		}
		for _, p := range cgroupPatterns {
			if m := p.re.FindStringSubmatch(path); m != nil {
				id := m[1]
				if p.engine == "lxc" || p.engine == "garden" {
					id = ""
				}
				d.engine(p.engine, id, "cgroup: "+path)
			}
		}
	}
}

// containerVar maps a systemd-style container= value to an engine.
func (d *detector) containerVar(v, source string) {
	engine := v
	switch {
	case v == "oci":
		engine = "unknown"
	case strings.HasPrefix(v, "lxc"):
		engine = "lxc"
	}
	d.engine(engine, "", source+"="+v)
}

func envVar(environ, key string) string {
	for _, kv := range bytes.Split([]byte(environ), []byte{0}) {
		if k, v, ok := bytes.Cut(kv, []byte("=")); ok && string(k) == key {
			return string(v)
		}
	}
	return ""
}
