package container

import (
	"slices"
	"testing"
	"testing/fstest"
)

const (
	dockerID  = "8ae8d1c774050edfd4133fd3b5eb3eecb53ac26891492ff2174601569c93643c"
	sandboxID = "57e2a9fa8f3423cf750055de8574a3a9db4d446464444986e311e7cf16dafab0"
	podUID    = "af7c9387-43b8-4b05-ad4c-1c7a1e580188"
)

// Captured on the test server (Docker 29, cgroup v2, private cgroupns).
const dockerMountinfo = `3684 3632 0:77 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/GMAA:/var/lib/docker/overlay2/l/UGCN,upperdir=/var/lib/docker/overlay2/67d0/diff,workdir=/var/lib/docker/overlay2/67d0/work,nouserxattr
3686 3684 0:88 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
3693 3684 259:2 /var/lib/docker/containers/` + dockerID + `/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/nvme0n1p2 rw
3694 3684 259:2 /var/lib/docker/containers/` + dockerID + `/hostname /etc/hostname rw,relatime - ext4 /dev/nvme0n1p2 rw
`

// A kind pod: kubelet and CRI paths nested under the node's Docker volume.
const kindMountinfo = `4603 4463 0:242 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/123/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/124/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/124/work,uuid=on,nouserxattr
4611 4603 259:2 /var/lib/docker/volumes/71a7/_data/lib/kubelet/pods/` + podUID + `/etc-hosts /etc/hosts rw,relatime - ext4 /dev/nvme0n1p2 rw
4613 4603 259:2 /var/lib/docker/volumes/71a7/_data/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/` + sandboxID + `/hostname /etc/hostname rw,relatime - ext4 /dev/nvme0n1p2 rw
`

// ctr run: no marker files, rootfs is a containerd snapshot.
const ctrMountinfo = `3685 3633 0:77 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2/work,uuid=on,nouserxattr
`

const podmanID = "1111111111111111111111111111111111111111111111111111111111111111"

const podmanMountinfo = `100 90 0:50 / / rw - overlay overlay rw,lowerdir=/var/lib/containers/storage/overlay/l/AAA
101 100 259:2 /var/lib/containers/storage/overlay-containers/` + podmanID + `/userdata/hostname /etc/hostname rw - ext4 /dev/sda1 rw
`

// Rootless podman 4.9 (captured): runroot without a storage/ component.
const podmanRootlessMountinfo = `141 84 0:34 / / rw,relatime - overlay overlay rw,lowerdir=/home/amic/.local/share/containers/storage/overlay/l/BVQ3,volatile,userxattr
137 141 254:0 /tmp/containers-user-1001/containers/overlay-containers/` + podmanID + `/userdata/hostname /etc/hostname rw,relatime - ext4 /dev/root rw
140 141 254:0 /tmp/containers-user-1001/containers/overlay-containers/` + podmanID + `/userdata/.containerenv /run/.containerenv rw,relatime - ext4 /dev/root rw
`

// MicroShift 4.20 / CRI-O pod (captured): hostname, resolv.conf and
// .containerenv come from the pod sandbox (54a0...), passwd from the
// container (f43d...).
const microshiftMountinfo = `500 400 0:60 / / rw - overlay overlay rw,lowerdir=/var/lib/containers/storage/overlay/l/X
501 500 252:3 /lib/kubelet/pods/294151c1-1e7d-4d15-99b2-2248c3614582/etc-hosts /etc/hosts rw - xfs /dev/vda3 rw
502 500 0:25 /containers/storage/overlay-containers/54a0a8c3c53287e48c2ea701eb26b14b404d87b492f601dae537c071546b74ae/userdata/resolv.conf /etc/resolv.conf rw - tmpfs tmpfs rw
503 500 0:25 /containers/storage/overlay-containers/54a0a8c3c53287e48c2ea701eb26b14b404d87b492f601dae537c071546b74ae/userdata/hostname /etc/hostname rw - tmpfs tmpfs rw
504 500 0:25 /containers/storage/overlay-containers/54a0a8c3c53287e48c2ea701eb26b14b404d87b492f601dae537c071546b74ae/userdata/.containerenv /run/.containerenv rw - tmpfs tmpfs rw
505 500 0:25 /containers/storage/overlay-containers/f43dcca08fbf8b3de85274c6499d6b27dd6fbc5adb5ec61c5babc823ce62cf5e/userdata/passwd /etc/passwd rw - tmpfs tmpfs rw
`

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// Captured in Kubernetes pods (containerd 2.2, Kata 4.2, guest 6.18) on
// the test server's kata-exp cluster: QEMU with the Go and Rust runtimes
// share files over virtiofs, Firecracker bind-mounts them from a tmpfs.
const (
	kataQEMUCmdline   = "tsc=reliable no_timer_check reboot=k root=/dev/pmem0p1 rootflags=dax,data=ordered,errors=remount-ro ro rootfstype=ext4 console=hvc0 quiet panic=1 nr_cpus=4 selinux=0 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service agent.cdh_api_timeout=50 cgroup_no_v1=all\n"
	kataQEMUMountinfo = `128 92 0:40 / / rw,relatime master:56 - virtiofs none rw
129 128 0:41 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
135 128 0:34 /5e146859a62b4cb635962ace55e235b1da7bde1a0ca886d91af15b017ac32260-b09a52916164989a-hosts /etc/hosts rw,relatime - virtiofs kataShared rw
137 128 0:34 /5e146859a62b4cb635962ace55e235b1da7bde1a0ca886d91af15b017ac32260-71c7d3f0179d1145-hostname /etc/hostname rw,relatime - virtiofs kataShared rw
141 128 0:44 / /var/run/secrets/kubernetes.io/serviceaccount ro,relatime - virtiofs none rw
`
	kataRsMountinfo = `128 92 0:40 / / rw,nodev,relatime master:56 - virtiofs none rw
135 128 0:34 /passthrough/sandbox-71b23673-etc-hosts /etc/hosts rw,nodev,relatime - virtiofs kataShared rw
`
	kataFCMountinfo = `130 94 254:32 / / rw,relatime master:56 - ext4 /dev/vdc rw,stripe=128
131 130 0:40 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
137 130 0:25 /kata-containers/shared/containers/77c72cd0af5e13b10327b83735ba069886fdddd1b63a7bfa804f8e1cf7c9a970-283c32ccfe9b8033-hosts /etc/hosts rw,nosuid,nodev - tmpfs tmpfs rw,size=407256k,nr_inodes=819200,mode=755
`
	// A runc pod on the same (vmm microVM) node.
	vmNodeCmdline = "console=ttyS0 reboot=k panic=1 root=/dev/vda rw ip=172.16.0.3::172.16.0.1:255.255.0.0::eth0:off\n"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name         string
		fs           fstest.MapFS
		env          map[string]string
		engine       string
		orchestrator string
		sandbox      string
		id           string
		podUID       string
	}{
		{
			name:   "host",
			fs:     fstest.MapFS{"proc/self/cgroup": file("0::/user.slice/user-1000.slice/session-3.scope\n")},
			engine: "",
		},
		{
			name: "docker cgroupns private",
			fs: fstest.MapFS{
				".dockerenv":          file(""),
				"proc/self/cgroup":    file("0::/\n"),
				"proc/self/mountinfo": file(dockerMountinfo),
			},
			engine: "docker",
			id:     dockerID,
		},
		{
			name:   "docker cgroupns host, no dockerenv",
			fs:     fstest.MapFS{"proc/self/cgroup": file("0::/system.slice/docker-" + dockerID + ".scope\n")},
			engine: "docker",
			id:     dockerID,
		},
		{
			name:   "docker cgroup v1",
			fs:     fstest.MapFS{"proc/self/cgroup": file("12:pids:/docker/" + dockerID + "\n11:memory:/docker/" + dockerID + "\n")},
			engine: "docker",
			id:     dockerID,
		},
		{
			name: "ctr",
			fs: fstest.MapFS{
				"proc/self/cgroup":    file("0::/default/amic-probe\n"),
				"proc/self/mountinfo": file(ctrMountinfo),
			},
			engine: "containerd",
		},
		{
			name: "kind pod",
			fs: fstest.MapFS{
				"proc/self/cgroup":    file("0::/\n"),
				"proc/self/mountinfo": file(kindMountinfo),
				"var/run/secrets/kubernetes.io/serviceaccount/token": file("x"),
			},
			env:          map[string]string{"KUBERNETES_SERVICE_HOST": "10.96.0.1"},
			engine:       "containerd",
			orchestrator: "kubernetes",
			podUID:       podUID,
		},
		{
			name: "kubernetes, nothing else visible",
			fs:   fstest.MapFS{"proc/self/cgroup": file("0::/\n")},
			env:  map[string]string{"KUBERNETES_SERVICE_HOST": "10.96.0.1"},

			engine:       "unknown",
			orchestrator: "kubernetes",
		},
		{
			name: "cri-o cgroup v1",
			fs: fstest.MapFS{"proc/self/cgroup": file(
				"1:memory:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1.slice/crio-" + podmanID + ".scope\n")},
			engine:       "cri-o",
			orchestrator: "kubernetes",
			id:           podmanID,
		},
		{
			name: "podman",
			fs: fstest.MapFS{
				"run/.containerenv":   file("engine=\"podman-5.2.1\"\nname=\"x\"\nid=\"" + podmanID + "\"\nrootless=0\n"),
				"proc/self/cgroup":    file("0::/\n"),
				"proc/self/mountinfo": file(podmanMountinfo),
			},
			env:    map[string]string{"container": "podman"},
			engine: "podman",
			id:     podmanID,
		},
		{
			name: "podman rootless, empty containerenv",
			fs: fstest.MapFS{
				"run/.containerenv":   file(""),
				"proc/self/mountinfo": file(podmanMountinfo),
			},
			engine: "podman",
			id:     podmanID,
		},
		{
			name: "podman rootless runroot",
			fs: fstest.MapFS{
				"run/.containerenv":   file(""),
				"proc/self/cgroup":    file("0::/\n"),
				"proc/self/mountinfo": file(podmanRootlessMountinfo),
			},
			env:    map[string]string{"container": "podman"},
			engine: "podman",
			id:     podmanID,
		},
		{
			name:   "podman cgroupns host, nested container cgroup",
			fs:     fstest.MapFS{"proc/self/cgroup": file("0::/machine.slice/libpod-" + podmanID + ".scope/container\n")},
			engine: "podman",
			id:     podmanID,
		},
		{
			name: "cri-o storage paths",
			fs: fstest.MapFS{
				"proc/self/mountinfo": file(podmanMountinfo),
			},
			env:          map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"},
			engine:       "cri-o",
			orchestrator: "kubernetes",
		},
		{
			name: "microshift pod",
			fs: fstest.MapFS{
				"run/.containerenv":   file(""),
				"proc/self/cgroup":    file("0::/\n"),
				"proc/self/mountinfo": file(microshiftMountinfo),
				"var/run/secrets/kubernetes.io/serviceaccount/token": file("x"),
			},
			env:          map[string]string{"KUBERNETES_SERVICE_HOST": "10.43.0.1"},
			engine:       "cri-o",
			orchestrator: "kubernetes",
			podUID:       "294151c1-1e7d-4d15-99b2-2248c3614582",
		},
		{
			name:   "systemd-nspawn",
			fs:     fstest.MapFS{"proc/1/environ": file("PATH=/bin\x00container=systemd-nspawn\x00")},
			engine: "systemd-nspawn",
		},
		{
			name:   "lxc via run/systemd/container",
			fs:     fstest.MapFS{"run/systemd/container": file("lxc\n")},
			engine: "lxc",
		},
		{
			name:   "openvz",
			fs:     fstest.MapFS{"proc/vz/veinfo": file("")},
			engine: "openvz",
		},
		{
			name: "gvisor",
			fs: fstest.MapFS{
				"proc/version":     file("Linux version 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016\n"),
				"proc/self/cgroup": file("7:pids:/\n6:memory:/\n5:job:/\n"),
			},
			engine:  "unknown",
			sandbox: "gvisor",
		},
		{
			name: "kata qemu in kubernetes",
			fs: fstest.MapFS{
				"proc/cmdline":        file(kataQEMUCmdline),
				"proc/self/mountinfo": file(kataQEMUMountinfo),
				"proc/self/cgroup":    file("0::/\n"),
				"var/run/secrets/kubernetes.io/serviceaccount/token": file("x"),
			},
			env:          map[string]string{"KUBERNETES_SERVICE_HOST": "10.96.0.1"},
			engine:       "unknown",
			orchestrator: "kubernetes",
			sandbox:      "kata",
		},
		{
			name:    "kata runtime-rs mounts only",
			fs:      fstest.MapFS{"proc/self/mountinfo": file(kataRsMountinfo)},
			engine:  "unknown",
			sandbox: "kata",
		},
		{
			name:    "kata firecracker mounts only",
			fs:      fstest.MapFS{"proc/self/mountinfo": file(kataFCMountinfo)},
			engine:  "unknown",
			sandbox: "kata",
		},
		{
			name:    "kata cmdline only",
			fs:      fstest.MapFS{"proc/cmdline": file(kataQEMUCmdline)},
			engine:  "unknown",
			sandbox: "kata",
		},
		{
			name: "runc on a VM node is not kata",
			fs: fstest.MapFS{
				"proc/cmdline":        file(vmNodeCmdline),
				"proc/self/mountinfo": file(dockerMountinfo),
			},
			engine: "docker",
			id:     dockerID,
		},
		{
			name: "gvisor under docker",
			fs: fstest.MapFS{
				".dockerenv":   file(""),
				"proc/version": file("Linux version 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016\n"),
			},
			engine:  "docker",
			sandbox: "gvisor",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := detect(tt.fs, env(tt.env))
			if r.Engine != tt.engine || r.Orchestrator != tt.orchestrator || r.Sandbox != tt.sandbox ||
				r.ContainerID != tt.id || r.PodUID != tt.podUID {
				t.Errorf("got engine=%q orchestrator=%q sandbox=%q id=%q pod=%q\nwant engine=%q orchestrator=%q sandbox=%q id=%q pod=%q\nevidence: %q",
					r.Engine, r.Orchestrator, r.Sandbox, r.ContainerID, r.PodUID,
					tt.engine, tt.orchestrator, tt.sandbox, tt.id, tt.podUID, r.Evidence)
			}
			if tt.engine != "" && len(r.Evidence) == 0 {
				t.Errorf("engine %q reported with no evidence", r.Engine)
			}
			if tt.engine == "" && len(r.Evidence) != 0 {
				t.Errorf("no engine but evidence %q", r.Evidence)
			}
		})
	}
}

func TestServiceAccountToken(t *testing.T) {
	r := detect(fstest.MapFS{"var/run/secrets/kubernetes.io/serviceaccount/token": file("x")}, env(nil))
	if !r.ServiceAccountToken {
		t.Error("token not reported")
	}
	if r := detect(fstest.MapFS{}, env(nil)); r.ServiceAccountToken {
		t.Error("token reported without one")
	}
}

func TestEvidenceDeduplicated(t *testing.T) {
	r := detect(fstest.MapFS{"proc/self/mountinfo": file(dockerMountinfo)}, env(nil))
	if !slices.Equal(r.Evidence, []string{"mountinfo: /etc/resolv.conf from /var/lib/docker/containers/", "mountinfo: /etc/hostname from /var/lib/docker/containers/"}) {
		t.Errorf("evidence = %q", r.Evidence)
	}
}
