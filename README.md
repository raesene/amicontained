## amicontained - fork

This is a fork of [the original amicontained](https://github.com/genuinetools/amicontained) to try and update some areas that have changed since the last release and also potentially to add some new features.

The main thing this addresses is the new syscalls that have been released since the last time amicontained was released. Without updated dependencies and the main program code you get an inaccurate list of blocked syscalls

## Supported architectures & OSs

This is *only* supported on AMD64/Linux as syscalls are platform dependent. In theory it is possible to make it work on ARM but not an immediate priority for me :)


## Syscall checking limitations

One of the limitations I noticed when reading the source is that it's not possible to directly check the availability of certain syscalls as doing so causes the process to break :D So there are some inevitable inaccuracies in syscall blocking.

## Usage

```bash
amicontained
```

Should do the basics and, if you're running in a Docker container, you'll get something like this as output

```bash
Container Runtime: docker
Has Namespaces:
        pid: true
        user: false
AppArmor Profile: docker-default (enforce)
Capabilities:
        BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
Looking for Docker.sock
Seccomp: filtering
Blocked Syscalls (68):
        SYSLOG SETSID USELIB USTAT SYSFS VHANGUP PIVOT_ROOT _SYSCTL ACCT SETTIMEOFDAY MOUNT UMOUNT2 SWAPON SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME IOPL IOPERM CREATE_MODULE INIT_MODULE DELETE_MODULE GET_KERNEL_SYMS QUERY_MODULE QUOTACTL NFSSERVCTL GETPMSG PUTPMSG AFS_SYSCALL TUXCALL SECURITY LOOKUP_DCOOKIE CLOCK_SETTIME VSERVER MBIND SET_MEMPOLICY GET_MEMPOLICY KEXEC_LOAD ADD_KEY REQUEST_KEY KEYCTL MIGRATE_PAGES UNSHARE MOVE_PAGES PERF_EVENT_OPEN FANOTIFY_INIT OPEN_BY_HANDLE_AT SETNS KCMP FINIT_MODULE KEXEC_FILE_LOAD BPF USERFAULTFD IO_URING_SETUP IO_URING_ENTER IO_URING_REGISTER OPEN_TREE MOVE_MOUNT FSOPEN FSCONFIG FSMOUNT FSPICK PIDFD_GETFD PROCESS_MADVISE MOUNT_SETATTR QUOTACTL_FD LANDLOCK_RESTRICT_SELF SET_MEMPOLICY_HOME_NODE
```

There's also a `-d` switch to get a load of debugging output as well :)
