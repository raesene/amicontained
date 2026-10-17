package procfs

import (
	"os"
	"slices"
	"strconv"
	"strings"
)

// Mount is one line of /proc/self/mountinfo.
type Mount struct {
	ID, Parent int
	// Root is the path inside the source filesystem. For bind mounts this
	// leaks host paths such as /var/lib/docker/containers/<id>/hostname.
	Root      string
	Point     string
	Options   []string // per-mount options (ro/rw, nosuid, ...)
	FSType    string
	Source    string
	SuperOpts string
}

// ReadOnly reports whether the mount itself is read-only.
func (m Mount) ReadOnly() bool { return slices.Contains(m.Options, "ro") }

// Mounts returns the parsed /proc/self/mountinfo.
func Mounts() []Mount {
	b, _ := os.ReadFile("/proc/self/mountinfo")
	return ParseMountinfo(string(b))
}

// ParseMountinfo parses mountinfo text (see proc(5)).
func ParseMountinfo(s string) []Mount {
	var out []Mount
	for _, line := range strings.Split(s, "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		f, g := strings.Fields(pre), strings.Fields(post)
		if len(f) < 6 || len(g) < 2 {
			continue
		}
		id, _ := strconv.Atoi(f[0])
		parent, _ := strconv.Atoi(f[1])
		m := Mount{
			ID:      id,
			Parent:  parent,
			Root:    unescape(f[3]),
			Point:   unescape(f[4]),
			Options: strings.Split(f[5], ","),
			FSType:  g[0],
			Source:  unescape(g[1]),
		}
		if len(g) > 2 {
			m.SuperOpts = g[2]
		}
		out = append(out, m)
	}
	return out
}

// MountFor returns the mount that path is on: the last-mounted entry whose
// mount point is path or a parent of it.
func MountFor(mounts []Mount, path string) (Mount, bool) {
	var best Mount
	found := false
	for _, m := range mounts {
		if m.Point == path || m.Point == "/" || strings.HasPrefix(path, m.Point+"/") {
			if !found || len(m.Point) >= len(best.Point) {
				best, found = m, true
			}
		}
	}
	return best, found
}

// unescape undoes mountinfo's octal escaping of space, tab, newline and
// backslash.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
