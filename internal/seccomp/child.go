//go:build linux

package seccomp

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// childEnv tells a re-executed amicontained binary to act as a probe child.
// Its value is "<method>:<first probe index>".
const childEnv = "AMICONTAINED_SECCOMP_PROBE"

// resultsFd is the inherited pipe the child reports results on.
const resultsFd = 3

// IsChild reports whether this process was started as a seccomp probe child.
func IsChild() bool {
	_, ok := os.LookupEnv(childEnv)
	return ok
}

// RunChild runs the probe child and exits. Results are written one per line
// to fd 3 without buffering, so the parent always knows which probe was in
// flight if the child is killed by the policy.
func RunChild() {
	method, startStr, _ := strings.Cut(os.Getenv(childEnv), ":")
	start, _ := strconv.Atoi(startStr)
	out := os.NewFile(resultsFd, "results")

	switch Method(method) {
	case MethodNotify:
		runNotifyChild(out, start)
	case MethodHeuristic:
		runHeuristicChild(out, start)
	default:
		fmt.Fprintf(out, "setup-error unknown method %q\n", method)
	}
	os.Exit(0)
}

func runNotifyChild(out *os.File, start int) {
	// The filter is installed on this thread only. It is never unlocked, so
	// the Go runtime will not reuse the filtered thread for other goroutines.
	runtime.LockOSThread()

	fd, err := installNotifyFilter()
	if err != nil {
		fmt.Fprintf(out, "setup-error installing notification filter: %v\n", err)
		return
	}
	go superviseNotifications(fd)

	// Self-test: a cookie-tagged getppid must reach our supervisor. If it
	// doesn't, results would be meaningless.
	if _, _, errno := unix.Syscall6(unix.SYS_GETPPID, 0, 0, 0, 0, 0, uintptr(probeCookie)); errno != notifiedErrno {
		fmt.Fprintf(out, "setup-error self-test: getppid returned %v\n", errno)
		return
	}
	fmt.Fprintf(out, "ready %d\n", unix.Gettid())

	probes := buildProbes(true)
	for i := start; i < len(probes); i++ {
		p := probes[i]
		if seccompExempt[p.name] {
			fmt.Fprintf(out, "r %d exempt\n", i)
			continue
		}
		_, _, errno := unix.Syscall6(uintptr(p.nr), p.args[0], p.args[1], p.args[2], p.args[3], p.args[4], uintptr(probeCookie))
		if errno == notifiedErrno {
			fmt.Fprintf(out, "r %d allow\n", i)
		} else {
			fmt.Fprintf(out, "r %d errno %d\n", i, int(errno))
		}
	}
}

// runHeuristicChild is the fallback when user notification is unavailable:
// it really executes each syscall with zero arguments and reports the errno.
func runHeuristicChild(out *os.File, start int) {
	fmt.Fprintf(out, "ready %d\n", unix.Gettid())

	probes := buildProbes(false)
	for i := start; i < len(probes); i++ {
		p := probes[i]
		if seccompExempt[p.name] {
			fmt.Fprintf(out, "r %d exempt\n", i)
			continue
		}
		if heuristicUnsafe[p.name] {
			fmt.Fprintf(out, "r %d skipped\n", i)
			continue
		}
		// Some calls block when allowed; run them asynchronously and treat
		// a slow return as allowed (rejections are immediate).
		errs := make(chan unix.Errno, 1)
		go func() {
			_, _, errno := unix.Syscall(uintptr(p.nr), 0, 0, 0)
			errs <- errno
		}()
		select {
		case errno := <-errs:
			if errno == 0 {
				fmt.Fprintf(out, "r %d ok\n", i)
			} else {
				fmt.Fprintf(out, "r %d errno %d\n", i, int(errno))
			}
		case <-time.After(100 * time.Millisecond):
			fmt.Fprintf(out, "r %d timeout\n", i)
		}
	}
}
