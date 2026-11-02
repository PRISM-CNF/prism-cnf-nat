package internal

import "testing"

func TestParseNATPolicyStaticPortMap(t *testing.T) {
	t.Parallel()

	policy, err := ParseNATPolicy([]byte(`
mode: static_port_map
virtual_ip: 172.16.5.10
virtual_port: 8080
backend_ip: 172.16.5.100
backend_port: 5201
`))
	if err != nil {
		t.Fatalf("ParseNATPolicy() error = %v", err)
	}

	if policy.Mode != NATModeStaticPortMap {
		t.Fatalf("Mode = %q, want %q", policy.Mode, NATModeStaticPortMap)
	}
	if got := policy.VirtualIP.String(); got != "172.16.5.10" {
		t.Fatalf("VirtualIP = %q, want 172.16.5.10", got)
	}
	if policy.VirtualPort != 8080 {
		t.Fatalf("VirtualPort = %d, want 8080", policy.VirtualPort)
	}
	if got := policy.BackendIP.String(); got != "172.16.5.100" {
		t.Fatalf("BackendIP = %q, want 172.16.5.100", got)
	}
	if policy.BackendPort != 5201 {
		t.Fatalf("BackendPort = %d, want 5201", policy.BackendPort)
	}
	if policy.Hash == "" {
		t.Fatal("Hash must not be empty")
	}
}

func TestParseNATPolicyEmpty(t *testing.T) {
	t.Parallel()

	policy, err := ParseNATPolicy([]byte("mode: empty\n"))
	if err != nil {
		t.Fatalf("ParseNATPolicy() error = %v", err)
	}

	if policy.Mode != NATModeEmpty {
		t.Fatalf("Mode = %q, want %q", policy.Mode, NATModeEmpty)
	}
}

func TestParseNATPolicyRejectsVirtualEqualsBackend(t *testing.T) {
	t.Parallel()

	_, err := ParseNATPolicy([]byte(`
mode: static_port_map
virtual_ip: 172.16.5.100
virtual_port: 5201
backend_ip: 172.16.5.100
backend_port: 5201
`))
	if err == nil {
		t.Fatal("ParseNATPolicy() error = nil, want non-nil")
	}
}

func TestParseNATPolicyRejectsInvalidPort(t *testing.T) {
	t.Parallel()

	_, err := ParseNATPolicy([]byte(`
mode: static_port_map
virtual_ip: 172.16.5.10
virtual_port: 0
backend_ip: 172.16.5.100
backend_port: 5201
`))
	if err == nil {
		t.Fatal("ParseNATPolicy() error = nil, want non-nil")
	}
}
