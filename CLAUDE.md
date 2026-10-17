# CLAUDE.md

Notes for Claude Code working in this repository.

## What this is

`amicontained` is a container introspection tool. It inspects the environment
it runs in and reports: container runtime, namespaces, AppArmor profile,
capabilities, Docker socket discovery, seccomp mode, and — the interesting
part — the list of syscalls blocked by the active seccomp policy.

This is a fork of `genuinetools/amicontained` maintained at
`github.com/raesene/amicontained`. The Go module path is still
`github.com/genuinetools/amicontained` for historical reasons — do not
rename it.

## Supported platform

Linux on amd64 and arm64. Syscall numbers are architecture-specific; the
per-arch tables in `internal/seccomp/zsyscalls_linux_*.go` are generated from
`golang.org/x/sys/unix`. arm64 builds and vets but has not yet been run on real
arm64 hardware.

## Repo layout

```
.
├── main.go              - CLI, non-seccomp checks, text/JSON output
├── internal/seccomp/    - seccomp assessment (see below)
│   ├── seccomp.go       - Probe(), report types, parent-side child management
│   ├── child.go         - re-exec'd probe child (notify + heuristic methods)
│   ├── filter.go        - our BPF notification filter and notify ioctls
│   ├── probes.go        - probe list, argument probes, skip/exempt lists
│   ├── zsyscalls_*.go   - GENERATED syscall tables (do not edit)
│   └── gen/             - table generator (go generate)
├── version/version.go   - ldflag-injected version/gitcommit vars
├── VERSION.txt          - version string baked into binaries (historical)
├── Makefile             - thin wrapper that includes basic.mk
├── basic.mk             - real build targets (build, static, vet, vendor...)
├── Dockerfile           - multi-stage alpine build
├── .goreleaser.yml      - release pipeline (linux/amd64+arm64, fully static)
├── .github/workflows/
│   └── release.yml      - runs goreleaser on tag push (v*)
└── vendor/              - vendored deps; always refresh with `go mod vendor`
```

## Building

- `make static` — CGO-disabled static build; produces `./amicontained`.
- `make build` — dynamic build (rarely used; release is always static).
- `go vet ./...` — run before committing.

The build embeds `version.VERSION` from `VERSION.txt` and `version.GITCOMMIT`
from git. An untracked/dirty tree appends `-dirty` to the commit hash.

## Seccomp check logic (the part that matters)

Lives in `internal/seccomp`. `main` calls `seccomp.IsChild()` first thing —
the prober re-executes the binary (`os.Executable()`) with
`AMICONTAINED_SECCOMP_PROBE=<method>:<start index>` and reads results from
fd 3. Do not add work before that check in `main()`.

- `/proc/self/status` `Seccomp:` 0 → report "disabled" and probe nothing
  (any denials are from caps/LSMs, not seccomp). 1 → strict, report only.
- **notify method (default):** the child locks its OS thread, sets
  `NO_NEW_PRIVS`, and installs a filter (that thread only, no TSYNC) returning
  `SECCOMP_RET_USER_NOTIF` for native-arch syscalls whose 6th arg is
  `probeCookie`. A supervisor goroutine answers notifications with errno
  `notifiedErrno` (4000). Kernel precedence across stacked filters means:
  outer ERRNO → probe sees that errno; outer KILL/TRAP → child dies (SIGSYS,
  or Go's exit 2 + "SIGSYS" on stderr for TRAP; a vanished probe thread for
  KILL_THREAD); outer ALLOW/LOG → sentinel errno, syscall never executed.
- A child that dies is restarted at the next index, so the probe list from
  `buildProbes()` must stay deterministic.
- Probe 0 is an unassigned number (1000) → "default action for unknown
  syscalls". runc/crun return ENOSYS for syscalls newer than their libseccomp
  knows, even if the profile allows them — that's real enforcement, not a bug.
- `argProbes` test argument-filtered calls (clone/unshare namespace flags,
  personality, AF_VSOCK, TIOCSTI). Notify method only.
- `seccompExempt` (`uretprobe`, `uprobe`): the kernel bypasses seccomp for
  these, so they'd really run. Reported as `exempt`, never probed.
- **heuristic fallback:** used if the notify filter can't be installed
  (kernel < 5.0, seccomp/prctl blocked). Really executes syscalls with zero
  args in the child; `heuristicUnsafe` lists ones that must never run
  (hang, exit, fork, or affect state outside the child: hostname, kexec,
  acct, vhangup...). Results are flagged as heuristic in the output.

### Extending for new kernel syscalls

1. `go get golang.org/x/sys@latest && go mod vendor`
2. `go generate ./internal/seccomp` — regenerates both arch tables.
3. If the new syscall is unsafe to execute with zero args, add it to
   `heuristicUnsafe`. If the kernel exempts it from seccomp, add it to
   `seccompExempt`.
4. Test in a container (below).

Prefer waiting for `x/sys` to catch up over hard-coding numeric literals.

## Safe testing workflow

Never run the binary or the seccomp tests on the host: the heuristic method
executes raw syscalls, and the socket scan walks the whole filesystem. Use
the test server (`ssh rorym@192.168.41.108`, Docker 29, kernel 7.0, sudo +
AppArmor available) or an iximiuz playground (`labctl`).

```bash
make static
CGO_ENABLED=0 go test -c -o /tmp/seccomp.test ./internal/seccomp
scp amicontained /tmp/seccomp.test rorym@192.168.41.108:/tmp/

# Hermetic tests: install a known outer filter (EPERM/ENOSYS/EACCES/
# KILL_PROCESS/KILL_THREAD/TRAP/LOG + a clone arg filter) and check every
# verdict. Must run with seccomp=unconfined so only the test's filter applies.
ssh rorym@192.168.41.108 docker run --rm --security-opt seccomp=unconfined \
    -v /tmp/seccomp.test:/t:ro alpine /t -test.v

# Real profiles
ssh rorym@192.168.41.108 docker run --rm -v /tmp/amicontained:/a:ro alpine /a
ssh rorym@192.168.41.108 docker run --rm -v /tmp/amicontained:/a:ro alpine /a -json
```

Pure unit tests (`-run 'ParseStatus|SyscallTable|JumpsInBounds|HeuristicClassifier|DisabledMode'`)
are safe locally.

Scenarios worth re-running after seccomp changes: default profile (compare
against moby's `default.json` from `github.com/moby/profiles`, tag
`seccomp/vX`), `--cap-add SYS_ADMIN` / `ALL` (cap-conditional rules),
`seccomp=unconfined` with caps dropped and with a deny-heavy AppArmor
profile (must report nothing blocked), the same AppArmor profile with the
default seccomp profile (must match the no-AppArmor result exactly), a profile
using ENOSYS/KILL/TRAP/LOG actions, and a profile that blocks `seccomp`
(must fall back to the heuristic with a warning).

## Release process

Releases are driven entirely by git tags matching `v*`.

1. Make sure `main` is clean and tests pass in the playground.
2. `git tag -a vX.Y.Z -m "vX.Y.Z"` and `git push origin vX.Y.Z`.
3. The `release.yml` workflow picks it up, runs goreleaser on Go (version
   pinned in the workflow), and publishes a GitHub Release with the static
   linux/amd64 binary tarball and checksums to `raesene/amicontained`.

Note: `.goreleaser.yml` hard-codes `release.github.owner: raesene`. If the
repo moves, update that field.

Note: `VERSION.txt` (`v0.4.9`) and the git tag sequence (`v0.0.x`) are
deliberately out of sync — `VERSION.txt` carries the upstream-fork heritage
version, the git tag drives the release artifact naming. Do not try to
"fix" this without asking.

## Recent work

- **Seccomp assessment rewritten** (October 2026) around stacked
  user-notification filters (see above). Replaced the errno-guessing loop,
  the hand-written 900-line `syscallName()` switch and the 335–423 skip
  range. Added `-json` and `-seccomp-method`, and arm64 support. Validated
  against moby's default profile: exact match for every syscall up to 456
  across default/SYS_ADMIN/all caps.
- Next phase (agreed with the user): runtime detection (broken on cgroup v2),
  more checks (NNP, SELinux, Landlock, namespaces, privileged indicators),
  bounded socket discovery, and replacing the abandoned deps
  (genuinetools/pkg, bpfd, gocapability, logrus, httpunix).
- Go 1.26, `golang.org/x/sys` v0.43.0.
