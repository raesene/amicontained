package procfs

import (
	"slices"
	"testing"
)

// Default Docker capabilities, captured on the test server.
const dockerStatus = `Name:	cat
Umask:	0022
State:	R (running)
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	2
Seccomp_filters:	1
`

func TestParseCapabilities(t *testing.T) {
	c, err := ParseCapabilities(ParseStatus(dockerStatus))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"chown", "dac_override", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap",
		"net_bind_service", "net_raw", "sys_chroot", "mknod", "audit_write", "setfcap"}
	if !slices.Equal(c.Effective.Names, want) {
		t.Errorf("effective = %q, want %q", c.Effective.Names, want)
	}
	if !slices.Equal(c.Bounding.Names, want) || !slices.Equal(c.Permitted.Names, want) {
		t.Errorf("bounding/permitted mismatch: %q %q", c.Bounding.Names, c.Permitted.Names)
	}
	if len(c.Inheritable.Names) != 0 || len(c.Ambient.Names) != 0 || c.Ambient.Hex != "0000000000000000" {
		t.Errorf("inheritable/ambient should be empty: %+v %+v", c.Inheritable, c.Ambient)
	}
}

func TestParseCapabilitiesErrors(t *testing.T) {
	if _, err := ParseCapabilities(ParseStatus("CapEff:\t0\n")); err == nil {
		t.Error("missing sets: want error")
	}
	bad := ParseStatus("CapInh:\tzz\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n")
	if _, err := ParseCapabilities(bad); err == nil {
		t.Error("bad hex: want error")
	}
}

func TestCapNames(t *testing.T) {
	// All caps on a 7.0 kernel: bits 0-40.
	all := CapNames(0x000001ffffffffff)
	if len(all) != 41 || all[0] != "chown" || all[38] != "perfmon" || all[39] != "bpf" || all[40] != "checkpoint_restore" {
		t.Errorf("all caps = %q", all)
	}
	if got := CapNames(1<<41 | 1); !slices.Equal(got, []string{"chown", "cap_41"}) {
		t.Errorf("unknown bit = %q", got)
	}
	if got := CapNames(0); got == nil || len(got) != 0 {
		t.Errorf("empty = %#v, want non-nil empty", got)
	}
}

func TestParseUIDMap(t *testing.T) {
	tests := []struct {
		in       string
		userns   bool
		mappings []UserMapping
	}{
		{"         0          0 4294967295\n", false, nil},
		{"         0     100000      65536\n", true, []UserMapping{{0, 100000, 65536}}},
		{"0 1000 1\n1 100000 65536\n", true, []UserMapping{{0, 1000, 1}, {1, 100000, 65536}}},
		{"", true, nil},
		{"0 0\n", false, nil},
	}
	for _, tt := range tests {
		userns, m := ParseUIDMap(tt.in)
		if userns != tt.userns || !slices.Equal(m, tt.mappings) {
			t.Errorf("ParseUIDMap(%q) = %v %v, want %v %v", tt.in, userns, m, tt.userns, tt.mappings)
		}
	}
}
