package sockets

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	dialTimeout    = 200 * time.Millisecond
	requestTimeout = time.Second
	// scanRequestTimeout is used for sockets the walk found whose names
	// don't suggest an engine; engines answer these probes in milliseconds.
	scanRequestTimeout = 300 * time.Millisecond
)

// identify connects to a socket and works out which API answers. Every
// request is read-only.
func identify(s Socket, timeout time.Duration) Socket {
	conn, err := net.DialTimeout("unix", s.Path, dialTimeout)
	if err != nil {
		s.Error = describeDialError(err)
		return s
	}
	conn.Close()

	// Sockets that should speak gRPC get it first so a gRPC server isn't
	// left to reject an HTTP/1 request before the right probe runs.
	grpcFirst := strings.HasPrefix(s.Guess, "containerd") || s.Guess == "cri-o" ||
		strings.HasPrefix(s.Guess, "kubelet") || strings.HasPrefix(s.Guess, "buildkit") || s.Guess == "cri-dockerd"
	probes := []func(*Socket, time.Duration) bool{probeHTTP, probeGRPC}
	if grpcFirst {
		probes = []func(*Socket, time.Duration) bool{probeGRPC, probeHTTP}
	}
	for _, p := range probes {
		if p(&s, timeout) {
			s.Accessible = true
			s.Error = ""
			return s
		}
	}
	if s.Error == "" {
		s.Error = "connected, but no known API answered"
	}
	return s
}

func dialer(path string) func(context.Context, string, string) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return d.DialContext(ctx, "unix", path)
	}
}

// probeHTTP tries the Docker-compatible API, which Podman also serves.
func probeHTTP(s *Socket, timeout time.Duration) bool {
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer(s.Path),
			ResponseHeaderTimeout: timeout,
			DisableKeepAlives:     true,
		},
	}
	resp, err := client.Get("http://localhost/_ping")
	if err != nil {
		return false
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()

	api, server := classifyPing(resp.Header)
	if api == "" {
		s.API, s.Product = "http", server
		return true
	}
	s.API = api
	s.Product = map[string]string{"docker": "Docker Engine", "podman": "Podman"}[api]

	resp, err = client.Get("http://localhost/version")
	if err != nil {
		return true
	}
	defer resp.Body.Close()
	var v struct{ Version, APIVersion string }
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v) == nil {
		s.Version = v.Version
		if v.APIVersion != "" {
			s.Version += " (API " + v.APIVersion + ")"
		}
	}
	return true
}

// classifyPing reads the /_ping headers. Podman sends Libpod-Api-Version and
// Server: Libpod/<ver>; Docker sends Api-Version and Server: Docker/<ver>.
func classifyPing(h http.Header) (api, server string) {
	server = h.Get("Server")
	switch {
	case h.Get("Libpod-Api-Version") != "" || strings.HasPrefix(server, "Libpod"):
		return "podman", server
	case h.Get("Api-Version") != "" || strings.HasPrefix(server, "Docker"):
		return "docker", server
	}
	return "", server
}

// gRPC methods tried in order. Both take an empty request message.
var grpcMethods = []struct {
	path, api string
	decode    func(map[int]string) (product, version string)
}{
	{
		// CRI VersionResponse: version=1 runtime_name=2 runtime_version=3
		// runtime_api_version=4. Served by containerd, CRI-O, cri-dockerd.
		"/runtime.v1.RuntimeService/Version", "cri",
		func(f map[int]string) (string, string) {
			v := f[3]
			if f[4] != "" {
				v += " (CRI " + f[4] + ")"
			}
			return f[2], v
		},
	},
	{
		// containerd VersionResponse: version=1 revision=2.
		"/containerd.services.version.v1.Version/Version", "containerd",
		func(f map[int]string) (string, string) { return "containerd", f[1] },
	},
}

// errUnimplemented is gRPC status 12: the server speaks gRPC but not this
// service.
var errUnimplemented = errors.New("grpc: unimplemented")

func probeGRPC(s *Socket, timeout time.Duration) bool {
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:       dialer(s.Path),
			Protocols:         &protocols,
			DisableKeepAlives: true,
		},
	}
	speaksGRPC := false
	for _, m := range grpcMethods {
		fields, err := grpcCall(&client, m.path)
		switch {
		case err == nil:
			s.API = m.api
			s.Product, s.Version = m.decode(fields)
			return true
		case errors.Is(err, errUnimplemented):
			speaksGRPC = true
		default:
			if !speaksGRPC {
				return false
			}
		}
	}
	if speaksGRPC {
		s.API, s.Product = "grpc", s.Guess
		return true
	}
	return false
}

// grpcCall makes a unary call with an empty request and returns the
// string fields of the response message.
func grpcCall(client *http.Client, method string) (map[int]string, error) {
	// A gRPC message is a 1-byte compression flag and a 4-byte length.
	req, err := http.NewRequest(http.MethodPost, "http://localhost"+method, bytes.NewReader(make([]byte, 5)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/grpc") {
		return nil, fmt.Errorf("not gRPC (content-type %q)", resp.Header.Get("Content-Type"))
	}
	// Errors may come as a trailers-only response, i.e. in the headers.
	status := resp.Trailer.Get("Grpc-Status")
	if status == "" {
		status = resp.Header.Get("Grpc-Status")
	}
	switch status {
	case "0":
	case "12":
		return nil, errUnimplemented
	default:
		msg := resp.Trailer.Get("Grpc-Message")
		if msg == "" {
			msg = resp.Header.Get("Grpc-Message")
		}
		return nil, fmt.Errorf("grpc status %s: %s", status, msg)
	}
	if len(body) < 5 {
		return nil, errors.New("grpc: short response")
	}
	n := binary.BigEndian.Uint32(body[1:5])
	if body[0] != 0 || int(n) > len(body)-5 {
		return nil, errors.New("grpc: unsupported or truncated message")
	}
	return protoStrings(body[5 : 5+n])
}

// protoStrings decodes the length-delimited fields of a protobuf message,
// which is all the version responses we read contain that we need.
func protoStrings(b []byte) (map[int]string, error) {
	fields := map[int]string{}
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("protobuf: bad key")
		}
		b = b[n:]
		field, wire := int(key>>3), key&7
		switch wire {
		case 0: // varint
			_, n = binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("protobuf: bad varint")
			}
			b = b[n:]
		case 1: // 64-bit
			if len(b) < 8 {
				return nil, errors.New("protobuf: short fixed64")
			}
			b = b[8:]
		case 2: // length-delimited
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return nil, errors.New("protobuf: bad length")
			}
			fields[field] = string(b[n : n+int(l)])
			b = b[n+int(l):]
		case 5: // 32-bit
			if len(b) < 4 {
				return nil, errors.New("protobuf: short fixed32")
			}
			b = b[4:]
		default:
			return nil, errors.New("protobuf: unsupported wire type " + strconv.Itoa(int(wire)))
		}
	}
	return fields, nil
}
