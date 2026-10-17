package lsm

import (
	"slices"
	"testing"
	"testing/fstest"

	"golang.org/x/sys/unix"
)

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

func allowAll(string) (bool, string) { return true, "" }

func noList() ([]uint64, error) { return nil, unix.ENOSYS }

func abi(n int) func() (int, error) { return func() (int, error) { return n, nil } }

func TestDetect(t *testing.T) {
	tests := []struct {
		name     string
		fs       fstest.MapFS
		safe     SafeToCall
		list     func() ([]uint64, error)
		landlock func() (int, error)

		active   []string
		source   string
		apparmor *Label
		selinux  *Label
		landOK   bool
		landErr  string
		confined bool
	}{
		{
			// Default Docker container on the test server: no securityfs,
			// lsm_list_modules blocked by seccomp (ENOSYS).
			name: "docker default",
			fs: fstest.MapFS{
				"sys/module/apparmor/parameters/enabled": file("Y\n"),
				"proc/self/attr/current":                 file("docker-default (enforce)\n"),
				"proc/self/attr/apparmor/current":        file("docker-default (enforce)\n"),
				"proc/sys/kernel/yama/ptrace_scope":      file("1\n"),
			},
			safe: func(n string) (bool, string) {
				if n == "lsm_list_modules" {
					return false, "blocked by seccomp (ENOSYS)"
				}
				return true, ""
			},
			list:     noList,
			landlock: abi(7),
			active:   []string{"capability", "apparmor", "yama", "landlock"},
			source:   "inferred",
			apparmor: &Label{Label: "docker-default (enforce)", Confining: true},
			landOK:   true,
			confined: true,
		},
		{
			name: "securityfs mounted, privileged",
			fs: fstest.MapFS{
				"sys/kernel/security/lsm":         file("lockdown,capability,landlock,yama,apparmor,ima,evm"),
				"proc/self/attr/apparmor/current": file("unconfined\n"),
			},
			safe:     allowAll,
			list:     noList,
			landlock: abi(7),
			active:   []string{"lockdown", "capability", "landlock", "yama", "apparmor", "ima", "evm"},
			source:   "securityfs",
			apparmor: &Label{Label: "unconfined"},
			landOK:   true,
		},
		{
			name: "lsm_list_modules",
			fs: fstest.MapFS{
				"proc/self/attr/current": file("system_u:system_r:container_t:s0:c1,c2\x00"),
				"sys/fs/selinux/enforce": file("1"),
			},
			safe:     allowAll,
			list:     func() ([]uint64, error) { return []uint64{108, 100, 105, 101, 999}, nil },
			landlock: func() (int, error) { return 0, unix.EOPNOTSUPP },
			active:   []string{"lockdown", "capability", "yama", "selinux", "lsm_999"},
			source:   "lsm_list_modules",
			selinux:  &Label{Label: "system_u:system_r:container_t:s0:c1,c2", Confining: true},
			landErr:  "built into the kernel but disabled at boot",
			confined: true,
		},
		{
			// vmm 6.1 kernel: SELinux built in, no policy loaded.
			name:     "selinux without policy",
			fs:       fstest.MapFS{"proc/self/attr/current": file("kernel\x00")},
			safe:     allowAll,
			list:     noList,
			landlock: func() (int, error) { return 0, unix.ENOSYS },
			active:   []string{"capability", "selinux"},
			source:   "inferred",
			selinux:  &Label{Label: "kernel", Note: "no SELinux policy loaded"},
			landErr:  "not supported by the kernel",
		},
		{
			name: "selinux spc_t and permissive",
			fs: fstest.MapFS{
				"sys/kernel/security/lsm": file("capability,selinux"),
				"proc/self/attr/current":  file("system_u:system_r:spc_t:s0"),
			},
			safe:     func(string) (bool, string) { return false, "blocked by seccomp (kill)" },
			list:     noList,
			landlock: abi(1),
			active:   []string{"capability", "selinux"},
			source:   "securityfs",
			selinux:  &Label{Label: "system_u:system_r:spc_t:s0", Note: "spc_t is unconfined"},
			landErr:  "blocked by seccomp (kill)",
		},
		{
			name: "apparmor complain",
			fs: fstest.MapFS{
				"sys/module/apparmor/parameters/enabled": file("Y"),
				"proc/self/attr/apparmor/current":        file("myprofile (complain)"),
			},
			safe:     allowAll,
			list:     noList,
			landlock: abi(4),
			active:   []string{"capability", "apparmor", "landlock"},
			source:   "inferred",
			apparmor: &Label{Label: "myprofile (complain)", Note: "profile in complain mode: violations are logged, not denied"},
			landOK:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := detect(tt.fs, tt.safe, tt.list, tt.landlock)
			if !slices.Equal(r.Active, tt.active) || r.Source != tt.source {
				t.Errorf("active = %q from %s, want %q from %s", r.Active, r.Source, tt.active, tt.source)
			}
			if !labelEqual(r.AppArmor, tt.apparmor) {
				t.Errorf("apparmor = %+v, want %+v", r.AppArmor, tt.apparmor)
			}
			if !labelEqual(r.SELinux, tt.selinux) {
				t.Errorf("selinux = %+v, want %+v", r.SELinux, tt.selinux)
			}
			if r.Landlock.Available != tt.landOK || r.Landlock.Error != tt.landErr {
				t.Errorf("landlock = %+v, want available=%t error=%q", r.Landlock, tt.landOK, tt.landErr)
			}
			if r.Confined() != tt.confined {
				t.Errorf("confined = %t, want %t", r.Confined(), tt.confined)
			}
		})
	}
}

func labelEqual(a, b *Label) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
