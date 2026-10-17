// Package procfs reads the handful of /proc and /run files amicontained
// needs. Every reader has a pure parse function alongside it so the parsing
// can be unit tested from fixtures.
package procfs

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Status returns /proc/self/status as key/value pairs.
func Status() (map[string]string, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil, err
	}
	return ParseStatus(string(b)), nil
}

// ParseStatus parses the "Key:\tvalue" lines of a /proc/<pid>/status file.
func ParseStatus(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if key, val, ok := strings.Cut(line, ":"); ok {
			m[key] = strings.TrimSpace(val)
		}
	}
	return m
}

// UserMapping is one line of /proc/self/uid_map.
type UserMapping struct {
	ContainerID int64 `json:"container_id"`
	HostID      int64 `json:"host_id"`
	Range       int64 `json:"range"`
}

// UserNamespace reports whether we are in a non-initial user namespace,
// judged by /proc/self/uid_map, and returns its mappings.
func UserNamespace() (bool, []UserMapping) {
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false, nil
	}
	return ParseUIDMap(string(b))
}

// ParseUIDMap parses a uid_map. The initial user namespace has the single
// identity mapping "0 0 4294967295"; anything else means a user namespace.
// An empty map is a user namespace whose mapping has not been written yet.
func ParseUIDMap(s string) (bool, []UserMapping) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return true, nil
	}
	if len(fields)%3 != 0 {
		return false, nil
	}
	var mappings []UserMapping
	for i := 0; i < len(fields); i += 3 {
		var v [3]int64
		for j := range v {
			n, err := strconv.ParseInt(fields[i+j], 10, 64)
			if err != nil {
				return false, nil
			}
			v[j] = n
		}
		if v == [3]int64{0, 0, 4294967295} {
			return false, nil
		}
		mappings = append(mappings, UserMapping{ContainerID: v[0], HostID: v[1], Range: v[2]})
	}
	return true, mappings
}

// CapSet is one capability set from /proc/self/status.
type CapSet struct {
	Hex   string   `json:"hex"`
	Names []string `json:"names"`
}

// Capabilities holds the five capability sets of the current thread.
type Capabilities struct {
	Effective   CapSet `json:"effective"`
	Permitted   CapSet `json:"permitted"`
	Inheritable CapSet `json:"inheritable"`
	Bounding    CapSet `json:"bounding"`
	Ambient     CapSet `json:"ambient"`
}

// ParseCapabilities decodes the Cap* fields of a parsed status file.
func ParseCapabilities(status map[string]string) (*Capabilities, error) {
	c := &Capabilities{}
	for _, f := range []struct {
		key string
		set *CapSet
	}{
		{"CapEff", &c.Effective},
		{"CapPrm", &c.Permitted},
		{"CapInh", &c.Inheritable},
		{"CapBnd", &c.Bounding},
		{"CapAmb", &c.Ambient},
	} {
		hex, ok := status[f.key]
		if !ok {
			return nil, fmt.Errorf("%s missing from /proc/self/status", f.key)
		}
		bits, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing %s %q: %w", f.key, hex, err)
		}
		*f.set = CapSet{Hex: hex, Names: CapNames(bits)}
	}
	return c, nil
}

// CapNames returns the names of the capabilities set in bits, in bit order.
// Bits beyond the table are named cap_<n>.
func CapNames(bits uint64) []string {
	names := []string{}
	for i := range 64 {
		if bits&(1<<i) == 0 {
			continue
		}
		if i < len(capNames) {
			names = append(names, capNames[i])
		} else {
			names = append(names, "cap_"+strconv.Itoa(i))
		}
	}
	return names
}

// capNames is indexed by capability number (include/uapi/linux/capability.h).
var capNames = []string{
	"chown",
	"dac_override",
	"dac_read_search",
	"fowner",
	"fsetid",
	"kill",
	"setgid",
	"setuid",
	"setpcap",
	"linux_immutable",
	"net_bind_service",
	"net_broadcast",
	"net_admin",
	"net_raw",
	"ipc_lock",
	"ipc_owner",
	"sys_module",
	"sys_rawio",
	"sys_chroot",
	"sys_ptrace",
	"sys_pacct",
	"sys_admin",
	"sys_boot",
	"sys_nice",
	"sys_resource",
	"sys_time",
	"sys_tty_config",
	"mknod",
	"lease",
	"audit_write",
	"audit_control",
	"setfcap",
	"mac_override",
	"mac_admin",
	"syslog",
	"wake_alarm",
	"block_suspend",
	"audit_read",
	"perfmon",
	"bpf",
	"checkpoint_restore",
}
