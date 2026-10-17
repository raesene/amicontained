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
amicontained [-json] [-seccomp-method auto|notify|heuristic|none] [-d]
amicontained -version
```

Running in a Docker container with the default profile gives something like:

```
Container Runtime: docker
	container id: 34be342a559e641b89f4034132272e9def885d07d6ec7672835c8d3aa9a8688d
	evidence: /.dockerenv exists
	evidence: mountinfo: /etc/hostname from /var/lib/docker/containers/
	...
Has Namespaces:
	pid: true
	user: false
AppArmor Profile: docker-default (enforce)
Capabilities:
	effective -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
	permitted -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
	inheritable -> none
	bounding -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
	ambient -> none
Docker Sockets:
	none found
Seccomp: filtering (filters: 1, method: user-notification)
	Default action for unknown syscalls: blocked (ENOSYS)
Blocked Syscalls (78):
	EPERM (66): syslog uselib ustat sysfs vhangup pivot_root _sysctl acct settimeofday mount umount2 ...
	ENOSYS (12): clone3 statmount listmount lsm_get_self_attr lsm_set_self_attr lsm_list_modules mseal ...
Argument Checks:
	clone(SIGCHLD) - create a process: allowed
	clone(CLONE_NEWUSER) - create a user namespace: blocked (EPERM)
	...
```

The runtime is worked out from several signals (marker files such as
`/.dockerenv` and `/run/.containerenv`, host paths leaked through
`/proc/self/mountinfo`, cgroup paths, the systemd `container=` convention and
Kubernetes service account/environment), and every signal that matched is
listed as evidence. It recognises Docker, Podman, containerd, CRI-O, LXC,
systemd-nspawn, OpenVZ and Garden, Kubernetes as an orchestrator, and gVisor
as a sandbox.

`-json` emits the same information as JSON, including the action and errno
for every syscall. `-d` adds debug output on stderr and lists allowed syscalls.
