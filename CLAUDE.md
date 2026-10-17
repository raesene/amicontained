# CLAUDE.md

Notes for Claude Code working in this repository. The README covers usage
and architecture for humans; this file covers what an agent needs to work
safely and the non-obvious design decisions behind the code.

## What this is

`amicontained` is a container introspection tool: run inside a container, it
reports the runtime, namespaces, capabilities, LSMs, privileged-container
indicators, reachable container-engine sockets, and the exact verdict of the
seccomp policy for every syscall, with a findings summary on top.

It started as a fork of `genuinetools/amicontained` (unmaintained) and lives
at `github.com/raesene/amicontained`, detached from the fork network, so PRs
target our own `main`. The Go module path is still
`github.com/genuinetools/amicontained` for historical reasons; do not
rename it.

Linux on amd64 and arm64 only. Dependencies: stdlib and `golang.org/x/sys`,
vendored. Keep it that way unless the user agrees otherwise.

## Repo layout

```
main.go                - flags, runs checks in order, JSON or text output
internal/seccomp/      - seccomp assessment
  seccomp.go           - Probe(), report types, SafeToCall, child management
  child.go             - re-exec'd probe child (notify + heuristic)
  filter.go            - our BPF notification filter and notify ioctls
  probes.go            - probe list, argument probes, skip/exempt lists
  zsyscalls_*.go       - GENERATED syscall tables (do not edit)
  gen/                 - table generator (go generate)
internal/container/    - runtime/orchestrator/sandbox detection with evidence
internal/procfs/       - /proc readers: status, caps, uid_map, mountinfo, namespaces
internal/lsm/          - active LSMs, AppArmor/SELinux/Smack labels, Landlock
internal/hardening/    - privileged indicators, read-only rootfs, cgroup limits
internal/sockets/      - engine socket discovery and API identification
internal/report/       - Report type, findings rules, text renderer
hack/                  - ansi2svg.py (README screenshot), seccomp-expected.py
docs/screenshot.png    - README screenshot (real output, see README)
version/, VERSION.txt  - ldflag-injected version
Makefile, basic.mk     - build/test targets
Dockerfile             - static build, FROM scratch image
.goreleaser.yml        - GoReleaser v2 config
.github/workflows/     - ci.yml (PRs, main), release.yml (v* tags)
```

## Build and test

- `make static` builds `./amicontained`. `go vet ./... && GOARCH=arm64 go vet ./...`
  before committing; CI also checks gofmt, `go mod tidy/vendor` and
  `go generate` produce no diff.
- `make test` runs only tests that are safe anywhere: fixture-driven
  packages, fake HTTP/gRPC servers on unix sockets in a temp dir, and the
  pure seccomp unit tests
  (`-run 'ParseStatus|SyscallTable|JumpsInBounds|HeuristicClassifier|DisabledMode|SafeToCall'`).
- **Never run the binary or the full seccomp tests on the dev host.** The
  heuristic method executes raw syscalls, the seccomp tests install filters,
  and the socket scan walks the filesystem and connects to every socket.
  Use the test server (below). `go test ./...` is not safe on the host.

## Safe testing workflow

Test server: `ssh rorym@192.168.41.108` (passwordless sudo, Docker 29.1.3,
kernel 7.0, cgroup v2, AppArmor, `kind`/`kubectl`, `ctr`, `vmm`). An
iximiuz playground (`labctl`) is the alternative.

```bash
make static
CGO_ENABLED=0 go test -c -o /tmp/seccomp.test ./internal/seccomp
scp amicontained /tmp/seccomp.test rorym@192.168.41.108:/tmp/

# Hermetic seccomp tests: they install a known outer filter (EPERM/ENOSYS/
# EACCES/KILL_PROCESS/KILL_THREAD/TRAP/LOG + a clone arg filter), so the
# container must be seccomp=unconfined.
ssh rorym@192.168.41.108 docker run --rm --security-opt seccomp=unconfined \
    -v /tmp/seccomp.test:/t:ro alpine /t -test.v

# Real profiles
ssh rorym@192.168.41.108 docker run --rm -v /tmp/amicontained:/a:ro alpine /a [-json|-v]
```

**Ground truth for seccomp.** `hack/seccomp-expected.py PROFILE.json
internal/seccomp/zsyscalls_linux_amd64.go CAPS REPORT.json` diffs a `-json`
report against verdicts computed from a moby-format profile
(`github.com/moby/profiles`, tag `seccomp/v0.1.0` for Docker 29; a copy may
be in `/tmp/amic-groundtruth/` on the dev machine). With Docker's default
profile, the only expected mismatches are `uretprobe` (`exempt` by design)
and 457-467 (ENOSYS: runc on the test server links libseccomp 2.5.5, which
predates them; that is real enforcement, not a bug).

Scenarios worth re-running after seccomp changes: default profile,
`--cap-add SYS_ADMIN`/`ALL` (cap-conditional rules), `seccomp=unconfined`
with caps dropped and with the deny-heavy AppArmor profile `amic-deny` on the
test server (must report nothing blocked), `amic-deny` with the default
seccomp profile (must match the no-AppArmor result exactly), a profile using
ENOSYS/KILL/TRAP/LOG actions, and a profile that blocks `seccomp` (must fall
back to the heuristic with a warning). The user specifically wanted proof
that capability and LSM denials are never reported as seccomp blocks.

**Other runtimes on the test server:**
- containerd: `sudo ctr run --rm --mount type=bind,src=/tmp/amicontained,dst=/a,options=rbind:ro docker.io/library/alpine:latest x /a`.
- Kubernetes (containerd): throwaway `kind create cluster`, `docker cp` the
  binary into the node, mount it via hostPath. Delete the cluster after.
- gVisor: `cd /tmp/gvisor && sudo ./runsc --network=none do /tmp/amicontained`
  (extracted release tarball; not registered with Docker). If `/tmp/gvisor`
  is gone, fetch `gvisor.tar.zstd` from the gVisor release bucket and verify
  the sha512.
- Podman and CRI-O run in vmm microVMs (see the vmm skill):
  - Podman: `sudo vmm create <vm> --cpus 2 --memory 2048 --disk 6144`, then
    `apt-get install podman`. The vmm rootfs has no `ca-certificates`;
    side-load images (`docker save` + `sudo vmm cp` + `podman load`) rather
    than weakening TLS. Rootless needs `--network=none`; the rootless API
    socket needs `XDG_RUNTIME_DIR=/run/user/<uid>` and
    `podman system service`.
  - CRI-O: `sudo vmm cluster create <name> --type openshift` (MicroShift,
    ~5 min, context `vmm-<name>`). Namespaces enforce PSA `restricted`;
    use `kubectl cp` rather than hostPath so the pod keeps `restricted-v2`.
  - The vmm 6.1 kernel has SELinux built in with no policy loaded
    (`/proc/self/attr/current` reads `kernel`).
- Check `sudo vmm list -a` for leftover VMs/clusters (`amic-podman`,
  `amic-ms` may still exist) and delete them when no longer needed.

## Design notes

Things that are not obvious from reading one file:

- **Ordering in `main`.** `seccomp.IsChild()` must stay the first thing in
  `main()`: the prober re-executes the binary with
  `AMICONTAINED_SECCOMP_PROBE=<method>:<start index>` and reads results from
  fd 3. The seccomp probe then runs before every other check, because `lsm`
  only makes real syscalls (`lsm_list_modules`, `landlock_create_ruleset`)
  if `seccomp.Report.SafeToCall` says they were allowed. Keep that for any
  future syscall-based check; a KILL profile must not take the tool down.
- **Seccomp notify method.** The child locks its OS thread, sets
  `NO_NEW_PRIVS`, installs a filter (that thread only, no TSYNC) returning
  `SECCOMP_RET_USER_NOTIF` for native-arch syscalls whose 6th arg is
  `probeCookie`, and a supervisor goroutine answers with errno
  `notifiedErrno` (4000). Outer ERRNO wins → that errno; outer KILL/TRAP →
  child dies (SIGSYS; Go's exit 2 + "SIGSYS" on stderr for TRAP; vanished
  thread for KILL_THREAD) and is restarted at the next index, so
  `buildProbes()` must stay deterministic; outer ALLOW/LOG → sentinel, never
  executed. Probe 0 is unassigned number 1000 → default action.
  `seccompExempt` (`uretprobe`, `uprobe`) are never probed because the
  kernel bypasses seccomp for them. `/proc/self/status` `Seccomp: 0` means
  probe nothing at all.
- **Heuristic fallback** really executes syscalls with zero args;
  `heuristicUnsafe` lists ones that must never run (hang, exit, fork, or
  affect state outside the child). Revisit it when adding syscalls.
- **New kernel syscalls:** `go get golang.org/x/sys@latest && go mod vendor`,
  `go generate ./internal/seccomp`, then update `heuristicUnsafe` /
  `seccompExempt` if needed. Prefer waiting for `x/sys` over hard-coding
  numbers.
- **Runtime detection** is signal-based with evidence. On cgroup v2
  `/proc/self/cgroup` is usually `0::/`, so bind-mount host paths in
  mountinfo do most of the work. CRI-O mounts hostname/resolv.conf/
  `.containerenv` from the pod *sandbox's* userdata dir, so under
  Kubernetes no container ID is taken from mount paths. CRI-O also creates
  an empty `/run/.containerenv`; Kubernetes signals turn that into `cri-o`.
  Podman nests the container at `libpod-<id>.scope/container` with
  `--cgroupns=host`; rootless bind mounts come from the runroot without a
  `storage/` component.
- **Namespaces** compare `/proc/self/ns/*` inodes with the kernel's fixed
  initial-namespace numbers (`0xEFFFFFFF` ipc … `0xEFFFFFF8` mnt). net/mnt
  only got fixed numbers recently (present on 7.0; on 6.1/6.12 they are the
  first dynamic numbers `0xF0000000`/`0xF0000001`), so they are "likely"
  unless the kernel is >= 7.0 or the fixed number is seen.
- **LSMs**: securityfs `lsm`, else `lsm_list_modules`, else inferred
  (partial; securityfs is not mounted in Docker containers). Inactive Smack
  returns EINVAL on `attr/smack/current`. Landlock enforcement cannot be
  queried, only availability.
- **Privileged indicators** use only masked paths that every engine masks;
  Docker's extra `/proc/interrupts` would make default podman look exposed.
- **Sockets**: bind-mounted sockets must come from mountinfo, because
  `getdents` reports the type of the file they were mounted over. Well-known
  paths are checked under every mount point too. Identification is
  read-only: HTTP `/_ping` + `/version`, and gRPC over stdlib h2c
  (`http.Protocols.SetUnencryptedHTTP2`) calling CRI then containerd
  `Version` with a hand-rolled protobuf decoder. Never call List-type
  methods.
- **Findings** (`report.ComputeFindings`) list only deviations from a
  default, isolated container. >= 5 privileged indicators collapse into one
  finding; inside a sandbox that is `info`, not `high`; user/time host
  namespaces are never findings; dangerous caps are checked in the bounding
  set. Add a `TestFindings` case for any new rule.
- **Text output** is ASCII apart from ANSI colour (TTY only, `NO_COLOR`,
  `-no-color`) and stays under ~80 columns (`TestWriteText` checks).

## Release process

1. `main` is green in CI and the scenarios above pass on the test server.
2. `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.
3. `release.yml` (tag pushes only) runs GoReleaser v2, which publishes
   linux/amd64 and linux/arm64 tarballs and checksums to
   `raesene/amicontained` (`release.github.owner` is hard-coded).

`VERSION.txt` (`v0.4.9`, baked into the binary via `AMICONTAINED_VERSION` in
`release.yml`) and the git tags (`v0.0.x`, artifact names) are deliberately
out of sync. Do not "fix" this without asking. `goreleaser check` and a
snapshot build can be run locally via the `goreleaser/goreleaser` image.

## Working with this user

- Present an assessment or plan before a large chunk of work, and ask
  clarifying questions up front; the user is happy to answer them.
- Verify behaviour claims empirically on the test server, and validate
  against ground truth where it exists.
- One PR per agreed piece of work. `gh` authenticates with a fine-grained
  token that cannot create PRs, so push the branch and give the user
  `https://github.com/raesene/amicontained/compare/main...<branch>`.
- Decisions already made: output format may change (no compatibility with
  the old text format), amd64 + arm64, stdlib + `x/sys` only, findings-first
  output with `-v` for detail and colour on a TTY.
- The user prefers committing CLAUDE.md alongside related work rather than
  after every change.

## Open items

- **arm64 has never run on real hardware.** It builds, vets and is
  released. Test on Graviton or an arm VM (qemu-user does not emulate
  seccomp faithfully).
- i386 (`int 0x80`) and x32 (`nr | 0x40000000`) ABIs are not probed;
  policies that only filter the native arch are a classic bypass. i386
  needs a Go assembly stub; x32 can use `Syscall6`.
- Untested on real systems: SELinux with an enforcing policy, AppArmor
  complain mode, Smack, cgroup v1, LXC, systemd-nspawn, OpenVZ, BuildKit and
  cri-dockerd sockets. Kata is not detected.
- The kernel version that introduced fixed net/mnt namespace inodes is not
  pinned down (somewhere after 6.12, at or before 7.0).
- Optional idea: a "denied by other layers" view (caps/LSM), clearly
  separate from the seccomp verdicts.
