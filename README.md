## amicontained - fork

This is a fork of [the original amicontained](https://github.com/genuinetools/amicontained) to try and update some areas that have changed since the last release and also potentially to add some new features.

The main thing this addresses is the new syscalls that have been released since the last time amicontained was released. Without updated dependencies and the main program code you get an inaccurate list of blocked syscalls

## Supported architectures & OSs

Linux on amd64 and arm64. Syscall tables are generated per architecture from
`golang.org/x/sys/unix`.

## How the seccomp check works

amicontained re-executes itself as a child process and stacks a second seccomp
filter on top of the one it inherited. That filter raises a *user notification*
for probe syscalls (identified by a cookie argument), and the kernel always
applies the highest-precedence action across all filters:

- if the container's policy blocks a syscall with an errno, the probe sees that errno;
- if the policy kills or traps, the child dies with `SIGSYS` and is restarted after that syscall;
- if the policy allows it, our filter fires and amicontained answers the
  notification itself — **the syscall is never executed**.

This means the result reflects only the seccomp policy (capabilities, AppArmor
and SELinux denials are not mistaken for seccomp blocks), every syscall can be
probed safely, and policies that return `ENOSYS` or use `KILL`/`TRAP` actions
are reported correctly. It also checks argument-filtered calls such as
`clone(CLONE_NEWUSER)` and `personality(ADDR_NO_RANDOMIZE)`.

User notification needs Linux 5.0+ and the `seccomp` syscall to be permitted
(it is under the Docker, containerd and Podman default profiles). Otherwise
amicontained falls back to an errno heuristic that really executes syscalls
with zero arguments; the output says when this happens, and those results can
include false positives from other security layers.

## Usage

```bash
amicontained [-v] [-json] [-no-color] [-seccomp-method auto|notify|heuristic|none]
             [-sockets scan|known|none] [-d]
amicontained -version
```

Running in a Docker container with the default profile and the Docker
socket mounted gives:

```
amicontained v0.4.9 - docker container 5679f97efa31

FINDINGS
  ! /run/docker.sock: Docker Engine API is accessible
    full control of the container engine, which usually means root on the host

RUNTIME
  engine        docker
  container id  5679f97efa31
  evidence      /.dockerenv exists (+3 more, -v)

ISOLATION
  namespaces    private: cgroup ipc mnt net pid uts
                host:    time user
  privileged    0/7 indicators (none present)
  rootfs        read-write
  cgroup        v2; memory none, cpu none, pids 70360

PRIVILEGES
  capabilities  effective = permitted = bounding (14)
                chown dac_override fowner fsetid kill setgid setuid setpcap
                net_bind_service net_raw sys_chroot mknod audit_write setfcap
                inheritable = ambient: none
  no_new_privs  false

SECURITY MODULES
  active        capability apparmor yama landlock (inferred, may be incomplete)
  apparmor      docker-default (enforce)
  landlock      available, ABI 8

SOCKETS
  /run/docker.sock  Docker Engine 29.1.3 (API 1.52)  ACCESSIBLE [well-known]

SECCOMP  filtering, 1 filter(s), method user-notification
  default       unknown syscalls: blocked (ENOSYS)
  blocked       78 syscalls
    EPERM (66)  syslog uselib ustat sysfs vhangup pivot_root _sysctl acct
                ...
    ENOSYS (12) clone3 statmount listmount lsm_get_self_attr lsm_set_self_attr
                lsm_list_modules mseal setxattrat getxattrat listxattrat
                removexattrat open_tree_attr
  arguments     clone(SIGCHLD)                  allowed
                clone(CLONE_NEWUSER)            blocked (EPERM)
                clone(CLONE_NEWNS)              blocked (EPERM)
                unshare(CLONE_NEWUSER)          blocked (EPERM)
                unshare(CLONE_NEWNS)            blocked (EPERM)
                unshare(CLONE_NEWNET)           blocked (EPERM)
                personality(PER_LINUX)          allowed
                personality(ADDR_NO_RANDOMIZE)  blocked (EPERM)
                socket(AF_VSOCK)                blocked (EPERM)
                ioctl(TIOCSTI)                  allowed
```

The output starts with **findings**: only the ways this environment differs
from a default, isolated container (`!` breaks isolation, `*` weakens it,
`i` is context). The sections after it hold the details; long lists are
summarised unless `-v` is given. Colour is used on a terminal unless
`NO_COLOR` is set or `-no-color` is passed. `-json` always contains
everything, including the findings.

The runtime is worked out from several signals (marker files such as
`/.dockerenv` and `/run/.containerenv`, host paths leaked through
`/proc/self/mountinfo`, cgroup paths, the systemd `container=` convention and
Kubernetes service account/environment), and every signal that matched is
listed as evidence. It recognises Docker, Podman, containerd, CRI-O, LXC,
systemd-nspawn, OpenVZ and Garden, Kubernetes as an orchestrator, and gVisor
as a sandbox.

Namespaces are compared against the kernel's fixed inode numbers for the
initial ("host") namespaces, so the answer is exact; on kernels older than
7.0 the net and mnt answers rely on allocation order and are marked
"(likely)". Privileged indicators are the usual effects of `--privileged`;
`--privileged` sets all seven, a default container from Docker, Podman,
containerd or CRI-O sets none (other than "no LSM confinement" where no LSM
policy is loaded). Checks that need real syscalls (`lsm_list_modules`,
`landlock_create_ruleset`) are only made if the seccomp probe found them
allowed, so a `KILL` profile cannot take the tool down.

Container sockets are looked for at well-known paths (Docker, Podman,
containerd, CRI-O, cri-dockerd, BuildKit, kubelet, including rootless and
under any mount point such as a mounted host root), at every bind-mounted
socket, and with a filesystem walk that skips pseudo-filesystems and stops
after 5 seconds. Each one is identified with read-only calls: `/_ping` and
`/version` for the Docker and Podman APIs, and the CRI and containerd
`Version` gRPC methods. An accessible engine socket is flagged, since it
usually means control of the host. `-sockets known` skips the walk and
`-sockets none` skips discovery entirely.

`-json` emits the same information as JSON, including the action and errno
for every syscall. `-v` also lists allowed syscalls; `-d` adds debug output
on stderr.
