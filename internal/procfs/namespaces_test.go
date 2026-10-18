package procfs

import (
	"errors"
	"testing"
)

// Inode sets captured on the test server.
var (
	// Host PID 1, kernel 7.0: every type has a fixed initial number.
	host70 = map[string]uint64{"cgroup": 4026531835, "ipc": 4026531839, "mnt": 4026531832, "net": 4026531833,
		"pid": 4026531836, "time": 4026531834, "user": 4026531837, "uts": 4026531838}
	// Host PID 1, kernel 6.1/6.12: net and mnt are the first dynamic numbers.
	host61 = map[string]uint64{"cgroup": 4026531835, "ipc": 4026531839, "mnt": 4026531841, "net": 4026531840,
		"pid": 4026531836, "time": 4026531834, "user": 4026531837, "uts": 4026531838}
	// Docker default container, kernel 7.0.
	docker70 = map[string]uint64{"cgroup": 4026532635, "ipc": 4026532633, "mnt": 4026532630, "net": 4026532636,
		"pid": 4026532634, "time": 4026531834, "user": 4026531837, "uts": 4026532632}
	// docker run --pid=host --net=host --ipc=host --uts=host --cgroupns=host, kernel 7.0.
	dockerHostNS70 = map[string]uint64{"cgroup": 4026531835, "ipc": 4026531839, "mnt": 4026532630, "net": 4026531833,
		"pid": 4026531836, "time": 4026531834, "user": 4026531837, "uts": 4026531838}
)

type verdict struct{ host, exact bool }

func classify(t *testing.T, inodes map[string]uint64, errs map[string]error, release string) map[string]verdict {
	t.Helper()
	got := map[string]verdict{}
	for _, ns := range ClassifyNamespaces(inodes, errs, release) {
		got[ns.Type] = verdict{ns.Host, ns.Exact}
	}
	return got
}

func TestClassifyNamespaces(t *testing.T) {
	tests := []struct {
		name    string
		inodes  map[string]uint64
		release string
		want    map[string]verdict
	}{
		{"host 7.0", host70, "7.0.0-15-generic", map[string]verdict{
			"cgroup": {true, true}, "ipc": {true, true}, "mnt": {true, true}, "net": {true, true},
			"pid": {true, true}, "time": {true, true}, "user": {true, true}, "uts": {true, true}}},
		{"host 6.1", host61, "6.1.172", map[string]verdict{
			"cgroup": {true, true}, "ipc": {true, true}, "mnt": {true, false}, "net": {true, false},
			"pid": {true, true}, "time": {true, true}, "user": {true, true}, "uts": {true, true}}},
		{"docker 7.0", docker70, "7.0.0-15-generic", map[string]verdict{
			"cgroup": {false, true}, "ipc": {false, true}, "mnt": {false, true}, "net": {false, true},
			"pid": {false, true}, "time": {true, true}, "user": {true, true}, "uts": {false, true}}},
		{"docker, unknown kernel", docker70, "", map[string]verdict{
			"cgroup": {false, true}, "ipc": {false, true}, "mnt": {false, false}, "net": {false, false},
			"pid": {false, true}, "time": {true, true}, "user": {true, true}, "uts": {false, true}}},
		{"docker host namespaces, unknown kernel", dockerHostNS70, "", map[string]verdict{
			"cgroup": {true, true}, "ipc": {true, true}, "mnt": {false, true}, "net": {true, true},
			"pid": {true, true}, "time": {true, true}, "user": {true, true}, "uts": {true, true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(t, tt.inodes, nil, tt.release)
			for typ, w := range tt.want {
				if got[typ] != w {
					t.Errorf("%s: got host=%t exact=%t, want host=%t exact=%t", typ, got[typ].host, got[typ].exact, w.host, w.exact)
				}
			}
		})
	}
}

func TestClassifyNamespacesError(t *testing.T) {
	inodes := map[string]uint64{}
	for k, v := range docker70 {
		inodes[k] = v
	}
	delete(inodes, "time")
	for _, ns := range ClassifyNamespaces(inodes, map[string]error{"time": errors.New("no such file")}, "") {
		if ns.Type == "time" && (ns.Error == "" || ns.Host) {
			t.Errorf("time: %+v, want error", ns)
		}
	}
}

func TestParseNSLink(t *testing.T) {
	if ino, err := parseNSLink("pid", "pid:[4026531836]"); err != nil || ino != 4026531836 {
		t.Errorf("got %d %v", ino, err)
	}
	if _, err := parseNSLink("pid", "net:[4026531836]"); err == nil {
		t.Error("type mismatch: want error")
	}
}

func TestClassifyNamespacesUnsupported(t *testing.T) {
	inodes := map[string]uint64{}
	for k, v := range docker70 {
		inodes[k] = v
	}
	delete(inodes, "time")
	for _, ns := range ClassifyNamespaces(inodes, map[string]error{"time": ErrUnsupported}, "") {
		if ns.Type == "time" && (!ns.Unsupported || ns.Error != "" || ns.Host) {
			t.Errorf("time: %+v, want unsupported", ns)
		}
	}
}
