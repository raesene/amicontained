//go:build linux

package seccomp

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// probeCookie is passed as the sixth syscall argument of every probe. Our
// notification filter only fires on syscalls carrying it, so the prober's
// own runtime syscalls are unaffected.
const probeCookie uint64 = 0x616d69636f6e7431 // "amicont1"

// notifiedErrno is the errno our supervisor answers intercepted probes with.
// It is far outside the range of real errnos, so seeing it means the outer
// policy allowed the call and it reached our filter.
const notifiedErrno = 4000

// Offsets into struct seccomp_data (little-endian on amd64 and arm64).
const (
	offArch    = 4
	offArg5Lo  = 16 + 5*8
	offArg5Hi  = offArg5Lo + 4
	retNotify  = unix.SECCOMP_RET_USER_NOTIF
	retAllowed = unix.SECCOMP_RET_ALLOW
)

// notifyFilter returns a BPF program that raises SECCOMP_RET_USER_NOTIF for
// native-arch syscalls whose sixth argument is probeCookie, and allows
// everything else.
func notifyFilter() []unix.SockFilter {
	stmt := func(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
	jeq := func(k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: jt, Jf: jf, K: k}
	}
	ld := uint16(unix.BPF_LD | unix.BPF_W | unix.BPF_ABS)
	ret := uint16(unix.BPF_RET | unix.BPF_K)
	return []unix.SockFilter{
		/* 0 */ stmt(ld, offArch),
		/* 1 */ jeq(auditArch, 0, 5),
		/* 2 */ stmt(ld, offArg5Lo),
		/* 3 */ jeq(uint32(probeCookie&0xffffffff), 0, 3),
		/* 4 */ stmt(ld, offArg5Hi),
		/* 5 */ jeq(uint32(probeCookie>>32), 0, 1),
		/* 6 */ stmt(ret, retNotify),
		/* 7 */ stmt(ret, retAllowed),
	}
}

// installNotifyFilter installs notifyFilter on the calling thread only (no
// TSYNC) and returns the notification listener fd.
func installNotifyFilter() (int, error) {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, err
	}
	filter := notifyFilter()
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// Kernel ABI structs for the user-notification ioctls (linux/seccomp.h).
type seccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type seccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Data  seccompData
}

type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// superviseNotifications answers every notification on fd with
// notifiedErrno until the fd is closed or errors.
func superviseNotifications(fd int) {
	for {
		var req seccompNotif // must be zeroed before each RECV
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_RECV, uintptr(unsafe.Pointer(&req)))
		if errno == unix.EINTR || errno == unix.ENOENT {
			continue
		}
		if errno != 0 {
			return
		}
		resp := seccompNotifResp{ID: req.ID, Error: -notifiedErrno}
		unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_SEND, uintptr(unsafe.Pointer(&resp)))
	}
}
