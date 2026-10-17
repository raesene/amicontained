// Package sockets finds container-management sockets (Docker, Podman,
// containerd, CRI-O, kubelet, BuildKit) and identifies which API answers on
// each, using read-only calls only.
package sockets

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/genuinetools/amicontained/internal/procfs"
)

// Mode selects how much searching Discover does.
type Mode string

const (
	ModeScan  Mode = "scan"  // well-known paths, then a bounded walk
	ModeKnown Mode = "known" // well-known paths only
	ModeNone  Mode = "none"
)

// Options controls Discover.
type Options struct {
	Mode Mode
	// Budget bounds the walk's wall-clock time; MaxEntries its size.
	Budget     time.Duration
	MaxEntries int
	Debug      io.Writer
}

// Report is what Discover found.
type Report struct {
	Mode    Mode      `json:"mode"`
	Sockets []Socket  `json:"sockets"`
	Scan    *ScanInfo `json:"scan,omitempty"`
}

// ScanInfo describes the filesystem walk.
type ScanInfo struct {
	Entries   int      `json:"entries"`
	Duration  string   `json:"duration"`
	Truncated string   `json:"truncated,omitempty"`
	Skipped   []string `json:"skipped,omitempty"`
}

// Socket is one discovered socket.
type Socket struct {
	Path   string `json:"path"`
	Source string `json:"source"` // env, well-known, mount, scan
	// Guess is what the path suggests, used when the API can't be identified.
	Guess string `json:"guess,omitempty"`
	// API is the protocol that answered: docker, podman, cri, containerd,
	// grpc or http. Empty if nothing did.
	API     string `json:"api,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	// Accessible means we connected and the API answered.
	Accessible bool   `json:"accessible"`
	Error      string `json:"error,omitempty"`
}

// Controls reports whether access to the socket amounts to control of a
// container engine (and so, usually, of the host).
func (s Socket) Controls() bool {
	return s.Accessible && (s.API == "docker" || s.API == "podman" || s.API == "cri" || s.API == "containerd")
}

type candidate struct{ path, guess string }

// wellKnown paths may contain globs. Order matters only for display.
var wellKnown = []candidate{
	{"/run/docker.sock", "docker"},
	{"/var/run/docker.sock", "docker"},
	{"/run/user/*/docker.sock", "docker (rootless)"},
	{"/run/podman/podman.sock", "podman"},
	{"/run/user/*/podman/podman.sock", "podman (rootless)"},
	{"/run/containerd/containerd.sock", "containerd"},
	{"/var/run/containerd/containerd.sock", "containerd"},
	{"/run/k3s/containerd/containerd.sock", "containerd (k3s)"},
	{"/run/crio/crio.sock", "cri-o"},
	{"/var/run/crio/crio.sock", "cri-o"},
	{"/run/cri-dockerd.sock", "cri-dockerd"},
	{"/var/run/cri-dockerd.sock", "cri-dockerd"},
	{"/run/buildkit/buildkitd.sock", "buildkit"},
	{"/run/user/*/buildkit/buildkitd.sock", "buildkit (rootless)"},
	{"/var/lib/kubelet/pod-resources/kubelet.sock", "kubelet pod-resources"},
	{"/var/lib/kubelet/device-plugins/kubelet.sock", "kubelet device-plugins"},
}

// guessByName recognises engine sockets mounted at unusual paths.
var guessByName = map[string]string{
	"docker.sock":      "docker",
	"podman.sock":      "podman",
	"containerd.sock":  "containerd",
	"crio.sock":        "cri-o",
	"cri-dockerd.sock": "cri-dockerd",
	"buildkitd.sock":   "buildkit",
	"kubelet.sock":     "kubelet",
	"dockershim.sock":  "dockershim",
}

// maxProbes bounds how many sockets found by the walk are probed.
const maxProbes = 64

// Discover finds and identifies sockets.
func Discover(opts Options) *Report {
	r := &Report{Mode: opts.Mode, Sockets: []Socket{}}
	if opts.Mode == ModeNone {
		return r
	}
	debug := opts.Debug
	if debug == nil {
		debug = io.Discard
	}

	seen := map[string]bool{}
	var cands []Socket
	add := func(path, guess, source string) {
		key := path
		if real, err := filepath.EvalSymlinks(path); err == nil {
			key = real
		}
		if seen[key] {
			return
		}
		seen[key] = true
		if guess == "" {
			guess = guessByName[filepath.Base(path)]
		}
		cands = append(cands, Socket{Path: path, Source: source, Guess: guess})
	}

	for _, env := range []string{"DOCKER_HOST", "CONTAINER_HOST"} {
		if p, ok := strings.CutPrefix(os.Getenv(env), "unix://"); ok && isSocket(p) {
			add(p, "", "env")
		}
	}
	mounts := procfs.Mounts()
	// Well-known paths under / and under every mount point, which finds
	// e.g. /host/run/docker.sock when the host's root is mounted in.
	prefixes := []string{""}
	for _, m := range mounts {
		if m.Point != "/" {
			prefixes = append(prefixes, m.Point)
		}
	}
	for _, prefix := range prefixes {
		for _, c := range wellKnown {
			matches, _ := filepath.Glob(prefix + c.path)
			for _, m := range matches {
				if isSocket(m) {
					add(m, c.guess, "well-known")
				}
			}
		}
	}
	// Sockets bind-mounted in. The walk can't see these: the directory
	// entry has the type of the file they were mounted over.
	for _, m := range mounts {
		if isSocket(m.Point) {
			add(m.Point, "", "mount")
		}
	}

	if opts.Mode == ModeScan {
		found, info := walk("/", mounts, opts.Budget, opts.MaxEntries, debug)
		r.Scan = info
		for i, p := range found {
			if i == maxProbes {
				if info.Truncated != "" {
					info.Truncated += "; "
				}
				info.Truncated += fmt.Sprintf("only the first %d sockets were probed", maxProbes)
				break
			}
			add(p, "", "scan")
		}
	}

	// Probe in parallel: most sockets a walk finds (D-Bus, systemd, agents)
	// speak neither protocol and only fail by timing out.
	r.Sockets = make([]Socket, len(cands))
	sem := make(chan struct{}, probeWorkers)
	var wg sync.WaitGroup
	for i, c := range cands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			timeout := requestTimeout
			if c.Source == "scan" && c.Guess == "" {
				timeout = scanRequestTimeout
			}
			fmt.Fprintf(debug, "sockets: probing %s\n", c.Path)
			r.Sockets[i] = identify(c, timeout)
		}()
	}
	wg.Wait()
	return r
}

const probeWorkers = 8

// Interesting reports whether a socket is worth showing in a summary: it
// answered a container API, or its path names one.
func (s Socket) Interesting() bool {
	return s.Guess != "" || s.Source != "scan" ||
		(s.API != "" && s.API != "http" && s.API != "grpc")
}

func isSocket(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode()&fs.ModeSocket != 0
}

// skipFSTypes are pseudo or remote filesystems that can't usefully hold
// engine sockets but can be slow or endless to walk.
var skipFSTypes = []string{
	"proc", "sysfs", "cgroup", "cgroup2", "devpts", "debugfs", "tracefs", "securityfs",
	"bpf", "pstore", "configfs", "fusectl", "hugetlbfs", "mqueue", "binfmt_misc", "autofs",
	"efivarfs", "selinuxfs", "nsfs", "nfs", "nfs4", "cifs", "smb3", "9p", "fuse.sshfs",
}

// walk looks for sockets under root without following symlinks, skipping
// pseudo and remote filesystems, within a time and entry budget.
func walk(root string, mounts []procfs.Mount, budget time.Duration, maxEntries int, debug io.Writer) ([]string, *ScanInfo) {
	skip := map[string]string{"/proc": "proc", "/sys": "sysfs"}
	for _, m := range mounts {
		if slices.Contains(skipFSTypes, m.FSType) {
			skip[m.Point] = m.FSType
		}
	}

	info := &ScanInfo{}
	start := time.Now()
	deadline := start.Add(budget)
	var found []string
	var skipped []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info.Entries++
		if maxEntries > 0 && info.Entries > maxEntries {
			info.Truncated = fmt.Sprintf("stopped after %d entries", maxEntries)
			return fs.SkipAll
		}
		if budget > 0 && info.Entries%256 == 0 && time.Now().After(deadline) {
			info.Truncated = fmt.Sprintf("stopped after %s", budget)
			return fs.SkipAll
		}
		if d.IsDir() {
			if fstype, ok := skip[p]; ok && p != root {
				skipped = append(skipped, p+" ("+fstype+")")
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSocket != 0 {
			fmt.Fprintf(debug, "sockets: found %s\n", p)
			found = append(found, p)
		}
		return nil
	})
	info.Duration = time.Since(start).Round(time.Millisecond).String()
	info.Skipped = skipped
	return found, info
}

// describeDialError turns a connect error into something readable.
func describeDialError(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EACCES, syscall.EPERM:
			return "permission denied"
		case syscall.ECONNREFUSED:
			return "connection refused (nothing listening)"
		case syscall.EPROTOTYPE:
			return "not a stream socket"
		}
	}
	return err.Error()
}
