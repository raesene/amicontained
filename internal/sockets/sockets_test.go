package sockets

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/genuinetools/amicontained/internal/procfs"
)

// serve starts srv on a unix socket in dir and returns its path.
func serve(t *testing.T, dir, name string, srv *http.Server) string {
	t.Helper()
	p := filepath.Join(dir, name)
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return p
}

func dockerLike(headers map[string]string, version string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		io.WriteString(w, "OK")
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, version)
	})
	return &http.Server{Handler: mux}
}

// protoString encodes one length-delimited protobuf field.
func protoString(field int, s string) []byte {
	b := binary.AppendUvarint(nil, uint64(field<<3|2))
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

// grpcServer answers the methods in replies with the given message, and
// everything else with UNIMPLEMENTED, over h2c.
func grpcServer(replies map[string][]byte) *http.Server {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	return &http.Server{
		Protocols: &p,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/grpc")
			msg, ok := replies[r.URL.Path]
			if !ok {
				w.Header().Set("Grpc-Status", "12") // trailers-only
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("Trailer", "Grpc-Status")
			frame := make([]byte, 5, 5+len(msg))
			binary.BigEndian.PutUint32(frame[1:], uint32(len(msg)))
			w.Write(append(frame, msg...))
			w.Header().Set("Grpc-Status", "0")
		}),
	}
}

func TestIdentify(t *testing.T) {
	dir := t.TempDir()

	docker := serve(t, dir, "docker.sock", dockerLike(map[string]string{
		"Api-Version": "1.52", "Server": "Docker/29.1.3 (linux)"},
		`{"Version":"29.1.3","ApiVersion":"1.52","Components":[]}`))
	podman := serve(t, dir, "podman.sock", dockerLike(map[string]string{
		"Api-Version": "1.41", "Libpod-Api-Version": "4.9.3", "Server": "Libpod/4.9.3 (linux)"},
		`{"Version":"4.9.3","ApiVersion":"1.41"}`))
	other := serve(t, dir, "web.sock", &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		http.NotFound(w, r)
	})})

	criVersion := slices.Concat(protoString(1, "0.1.0"), protoString(2, "cri-o"), protoString(3, "1.33.6"), protoString(4, "v1"))
	crio := serve(t, dir, "crio.sock", grpcServer(map[string][]byte{"/runtime.v1.RuntimeService/Version": criVersion}))
	ctrd := serve(t, dir, "containerd.sock", grpcServer(map[string][]byte{
		"/containerd.services.version.v1.Version/Version": slices.Concat(protoString(1, "v2.2.1"), protoString(2, "abc")),
	}))
	kubelet := serve(t, dir, "kubelet.sock", grpcServer(nil))

	// A listener that never answers.
	l, err := net.Listen("unix", filepath.Join(dir, "silent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// A socket file with nothing listening.
	l2, _ := net.Listen("unix", filepath.Join(dir, "dead.sock"))
	l2.(*net.UnixListener).SetUnlinkOnClose(false)
	l2.Close()

	tests := []struct {
		sock       Socket
		api        string
		product    string
		version    string
		accessible bool
		errPrefix  string
	}{
		{Socket{Path: docker, Guess: "docker"}, "docker", "Docker Engine", "29.1.3 (API 1.52)", true, ""},
		{Socket{Path: podman, Guess: "podman"}, "podman", "Podman", "4.9.3 (API 1.41)", true, ""},
		{Socket{Path: other}, "http", "nginx", "", true, ""},
		{Socket{Path: crio, Guess: "cri-o"}, "cri", "cri-o", "1.33.6 (CRI v1)", true, ""},
		{Socket{Path: ctrd, Guess: "containerd"}, "containerd", "containerd", "v2.2.1", true, ""},
		{Socket{Path: ctrd}, "containerd", "containerd", "v2.2.1", true, ""}, // no guess: HTTP first
		{Socket{Path: kubelet, Guess: "kubelet pod-resources"}, "grpc", "kubelet pod-resources", "", true, ""},
		{Socket{Path: filepath.Join(dir, "silent.sock")}, "", "", "", false, "connected, but no known API answered"},
		{Socket{Path: filepath.Join(dir, "dead.sock")}, "", "", "", false, "connection refused"},
	}
	for _, tt := range tests {
		t.Run(filepath.Base(tt.sock.Path)+"/"+tt.sock.Guess, func(t *testing.T) {
			start := time.Now()
			got := identify(tt.sock, requestTimeout)
			if got.API != tt.api || got.Product != tt.product || got.Version != tt.version ||
				got.Accessible != tt.accessible || !strings.HasPrefix(got.Error, tt.errPrefix) {
				t.Errorf("got %+v", got)
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("took %s", d)
			}
		})
	}
}

func TestClassifyPing(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "Libpod/5.0.0 (linux)")
	if api, _ := classifyPing(h); api != "podman" {
		t.Errorf("libpod server: %q", api)
	}
	if api, _ := classifyPing(http.Header{}); api != "" {
		t.Errorf("no headers: %q", api)
	}
}

func TestProtoStrings(t *testing.T) {
	msg := slices.Concat(
		[]byte{0x08, 0x96, 0x01}, // field 1 varint 150
		protoString(2, "hello"),
		[]byte{0x1d, 1, 2, 3, 4}, // field 3 fixed32
		protoString(4, ""),
	)
	f, err := protoStrings(msg)
	if err != nil || f[2] != "hello" || f[4] != "" || len(f) != 2 {
		t.Errorf("got %v %v", f, err)
	}
	if _, err := protoStrings([]byte{0x12, 0x10, 'a'}); err == nil {
		t.Error("truncated: want error")
	}
}

func TestWalk(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"a/b", "proc", "skipme/deep"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	for _, s := range []string{"a/b/one.sock", "skipme/deep/hidden.sock", "proc/x.sock"} {
		l, err := net.Listen("unix", filepath.Join(dir, s))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
	}
	os.WriteFile(filepath.Join(dir, "a/file"), nil, 0o644)
	os.Symlink(filepath.Join(dir, "skipme"), filepath.Join(dir, "a/link"))

	mounts := []procfs.Mount{{Point: filepath.Join(dir, "skipme"), FSType: "sysfs"}, {Point: filepath.Join(dir, "proc"), FSType: "proc"}}
	found, info := walk(dir, mounts, time.Minute, 0, io.Discard)
	if want := []string{filepath.Join(dir, "a/b/one.sock")}; !slices.Equal(found, want) {
		t.Errorf("found %q, want %q", found, want)
	}
	if len(info.Skipped) != 2 || info.Truncated != "" {
		t.Errorf("info = %+v", info)
	}

	_, info = walk(dir, nil, time.Minute, 3, io.Discard)
	if !strings.Contains(info.Truncated, "3 entries") {
		t.Errorf("entry cap: %+v", info)
	}
}
