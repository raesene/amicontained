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

Linux / amd64 only. Syscall numbers are architecture-specific, and the
syscall enumeration logic in `main.go` is hard-coded to the x86_64 table.

## Repo layout

```
.
├── main.go              - everything; CLI, checks, and syscallName() table
├── version/version.go   - ldflag-injected version/gitcommit vars
├── VERSION.txt          - version string baked into binaries (historical)
├── Makefile             - thin wrapper that includes basic.mk
├── basic.mk             - real build targets (build, static, vet, vendor...)
├── Dockerfile           - multi-stage alpine build
├── .goreleaser.yml      - release pipeline (linux/amd64, fully static)
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

## Syscall check logic (the part that matters)

All of it lives in `main.go`:

- `seccompIter()` — iterates `id` from `0` to `unix.SYS_OPEN_TREE_ATTR`,
  attempts each syscall with zero args, and classifies by errno:
  - `EPERM` / `EACCES` → blocked (seccomp denied it)
  - `EOPNOTSUPP` → ignored
  - anything else (including `ENOSYS` on unsupported kernels) → allowed
- `syscallName(e int) string` — giant `switch` mapping syscall number to
  human-readable name. Must be kept in sync with the loop upper bound.

### Skipping dangerous syscalls

The loop deliberately `continue`s past syscalls that would crash or hang the
probing process if they succeeded:

- `rt_sigreturn`, `select`, `pause`, `pselect6`, `ppoll` — hang
- `exit`, `exit_group` — terminate the probe process
- `clone`, `clone3`, `fork`, `vfork` — fork bomb / orphan children
- `seccomp` — would change our own policy
- `sync`, `tkill` — observed to misbehave
- range `335..423` — not valid x86_64 syscalls (gap in the table)

If you add a new syscall case that turns out to misbehave during playground
testing, add it to the skip list rather than removing the case from
`syscallName()`.

### Extending for new kernel syscalls

When the kernel adds new syscalls:

1. `go get golang.org/x/sys@latest && go mod vendor`
2. Check `vendor/golang.org/x/sys/unix/zsysnum_linux_amd64.go` for new
   `SYS_*` constants above the current upper bound.
3. Add a `case unix.SYS_FOO:` arm to `syscallName()` for each new one.
4. Bump the loop bound in `seccompIter()` to the new highest constant.
5. Test in the playground (see below) before releasing.

Upstream Linux may have syscalls that `x/sys` hasn't exposed yet as named
constants. Prefer waiting for `x/sys` to catch up over hard-coding numeric
literals.

## Safe testing workflow

Running `amicontained` on the host is unsafe — the syscall probe makes raw
syscalls that can destabilise the host, and the current loop calls
`getValidSockets("/")` which walks the entire root filesystem. Always test
inside a container.

The playground pattern used for v0.0.4 release testing:

```bash
# 1. Build
make static

# 2. Spin up an iximiuz Labs docker playground (has docker pre-installed)
PG=$(labctl playground start docker --quiet)

# 3. Ship the binary over
labctl cp ./amicontained $PG:/tmp/amicontained
labctl ssh $PG -- chmod +x /tmp/amicontained

# 4. Run it inside a stock alpine container (default Docker seccomp profile)
labctl ssh $PG -- docker run --rm \
    -v /tmp/amicontained:/amicontained:ro \
    alpine /amicontained

# 5. Debug mode prints every syscall being probed — use this to verify new
#    entries are actually firing:
labctl ssh $PG -- docker run --rm \
    -v /tmp/amicontained:/amicontained:ro \
    alpine /amicontained -d

# 6. Clean up
labctl playground destroy $PG
```

A clean run reports `Container Runtime: not-found` (the alpine container
isn't detected as a known runtime by `bpfd/proc`), followed by namespaces,
AppArmor, capabilities, seccomp mode, and a list of blocked syscalls.
Exit code should be 0.

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

- **Go toolchain bumped to 1.26** (April 2026) — updated `go.mod` directive
  and the `go-version` pin in `.github/workflows/release.yml`. `Dockerfile`
  uses `golang:alpine` (unpinned) so it floats automatically.
- **`golang.org/x/sys` bumped v0.33.0 → v0.43.0** to expose new syscall
  constants.
- **Syscall probe extended to 467** — added `STATMOUNT`, `LISTMOUNT`,
  `LSM_GET_SELF_ATTR`, `LSM_SET_SELF_ATTR`, `LSM_LIST_MODULES`, `MSEAL`,
  `SETXATTRAT`, `GETXATTRAT`, `LISTXATTRAT`, `REMOVEXATTRAT`,
  `OPEN_TREE_ATTR`. Also fixed a pre-existing off-by-N: the loop bound had
  been `unix.SYS_FCHMODAT2` (452) while the comment and `syscallName()`
  claimed coverage up to 456, so 453–456 were silently never probed.
