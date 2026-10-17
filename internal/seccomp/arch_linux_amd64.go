//go:build linux && amd64

package seccomp

import "golang.org/x/sys/unix"

const (
	supportedArch = true
	auditArch     = unix.AUDIT_ARCH_X86_64
)
