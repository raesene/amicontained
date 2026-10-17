//go:build linux && arm64

package seccomp

import "golang.org/x/sys/unix"

const (
	supportedArch = true
	auditArch     = unix.AUDIT_ARCH_AARCH64
)
