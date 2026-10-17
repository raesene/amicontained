//go:build linux && !amd64 && !arm64

package seccomp

const (
	supportedArch = false
	auditArch     = 0
)

var syscallTable []syscallEntry
