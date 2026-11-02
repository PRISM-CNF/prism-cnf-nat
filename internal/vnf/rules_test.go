package vnf

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"nse-ovs-nat/internal"
)

func TestRenderStaticPortMapCommands(t *testing.T) {
	t.Parallel()

	zone := connectionTrackingZone("conn-1")
	commands := renderStaticPortMapCommands(
		FlowInfo{
			ConnectionID:     "conn-1",
			IngressInterface: "if-in",
			EgressInterface:  "if-out",
		},
		&internal.NATPolicy{
			Mode:        internal.NATModeStaticPortMap,
			VirtualIP:   mustIPv4Addr(t, "172.16.5.10"),
			VirtualPort: 8080,
			BackendIP:   mustIPv4Addr(t, "172.16.5.100"),
			BackendPort: 5201,
		},
	)

	if len(commands) != 10 {
		t.Fatalf("command count = %d, want 10", len(commands))
	}

	if got := strings.Join(commands[0], " "); !strings.Contains(got, "dev if-in ingress chain 0 pref 100") || !strings.Contains(got, "ip_proto tcp") || !strings.Contains(got, "dst_ip 172.16.5.10") || !strings.Contains(got, "dst_port 8080") || !strings.Contains(got, fmt.Sprintf("action ct zone %d pipe action goto chain 10", zone)) {
		t.Fatalf("unexpected TCP forward lookup command: %s", got)
	}
	if got := strings.Join(commands[1], " "); !strings.Contains(got, "dev if-in ingress chain 10 pref 110") || !strings.Contains(got, "ip_proto tcp") || !strings.Contains(got, "ct_state +trk+new") || !strings.Contains(got, fmt.Sprintf("action ct commit zone %d mark 1 nat dst addr 172.16.5.100 port 5201", zone)) {
		t.Fatalf("unexpected TCP forward commit command: %s", got)
	}
	if got := strings.Join(commands[4], " "); !strings.Contains(got, "dev if-out ingress chain 20 pref 210") || !strings.Contains(got, "ip_proto tcp") || !strings.Contains(got, "src_ip 172.16.5.100") || !strings.Contains(got, "src_port 5201") || !strings.Contains(got, fmt.Sprintf("action ct nat zone %d", zone)) {
		t.Fatalf("unexpected TCP reverse translate command: %s", got)
	}
	if got := strings.Join(commands[5], " "); !strings.Contains(got, "dev if-in ingress chain 0 pref 120") || !strings.Contains(got, "ip_proto udp") || !strings.Contains(got, "dst_ip 172.16.5.10") || !strings.Contains(got, "dst_port 8080") || !strings.Contains(got, fmt.Sprintf("action ct zone %d pipe action goto chain 10", zone)) {
		t.Fatalf("unexpected UDP forward lookup command: %s", got)
	}
	if got := strings.Join(commands[6], " "); !strings.Contains(got, "dev if-in ingress chain 10 pref 130") || !strings.Contains(got, "ip_proto udp") || !strings.Contains(got, "ct_state +trk+new") || !strings.Contains(got, fmt.Sprintf("action ct commit zone %d mark 1 nat dst addr 172.16.5.100 port 5201", zone)) {
		t.Fatalf("unexpected UDP forward commit command: %s", got)
	}
	if got := strings.Join(commands[9], " "); !strings.Contains(got, "dev if-out ingress chain 20 pref 230") || !strings.Contains(got, "ip_proto udp") || !strings.Contains(got, "src_ip 172.16.5.100") || !strings.Contains(got, "src_port 5201") || !strings.Contains(got, fmt.Sprintf("action ct nat zone %d", zone)) {
		t.Fatalf("unexpected UDP reverse translate command: %s", got)
	}
}

func TestApplyStaticPortMapPolicyLifecycle(t *testing.T) {
	t.Parallel()

	runner := &recordingTCRunner{}
	flow := FlowInfo{
		ConnectionID:     "conn-1",
		IngressInterface: "if-in",
		EgressInterface:  "if-out",
	}
	policy := &internal.NATPolicy{
		Mode:        internal.NATModeStaticPortMap,
		VirtualIP:   mustIPv4Addr(t, "172.16.5.10"),
		VirtualPort: 8080,
		BackendIP:   mustIPv4Addr(t, "172.16.5.100"),
		BackendPort: 5201,
		Hash:        "abcd1234",
	}
	session := &watchedRuleSession{
		runner: runner,
		options: Options{
			RulesPath:        "/etc/nse-nat/rules.yaml",
			RulePollInterval: defaultRulePollInterval,
			TCBinary:         defaultTCBinary,
		},
		flow:  flow,
		state: newSessionState(),
	}

	if err := session.applyPolicy(context.Background(), policy); err != nil {
		t.Fatalf("applyPolicy() error = %v", err)
	}

	if len(runner.commands) != 14 {
		t.Fatalf("command count after apply = %d, want 14", len(runner.commands))
	}
	if got, ok := session.state.Load(StateKeyNATMode); !ok || got != string(internal.NATModeStaticPortMap) {
		t.Fatalf("state nat mode = %v, %v; want %q, true", got, ok, internal.NATModeStaticPortMap)
	}
	if got, ok := session.state.Load(StateKeyNATVirtualPort); !ok || got != "8080" {
		t.Fatalf("state nat virtual port = %v, %v; want 8080, true", got, ok)
	}
	if got, ok := session.state.Load(StateKeyNATBackendPort); !ok || got != "5201" {
		t.Fatalf("state nat backend port = %v, %v; want 5201, true", got, ok)
	}

	if err := cleanupTCState(context.Background(), runner, flow); err != nil {
		t.Fatalf("cleanupTCState() error = %v", err)
	}
	if len(runner.commands) != 16 {
		t.Fatalf("command count after cleanup = %d, want 16", len(runner.commands))
	}
}

func TestCleanupTCStateIgnoresMissingClsactQdisc(t *testing.T) {
	t.Parallel()

	runner := &missingQdiscTCRunner{}
	flow := FlowInfo{
		IngressInterface: "if-in",
		EgressInterface:  "if-out",
	}

	if err := cleanupTCState(context.Background(), runner, flow); err != nil {
		t.Fatalf("cleanupTCState() error = %v", err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("command count after cleanup = %d, want 2", len(runner.commands))
	}
}

func mustIPv4Addr(t *testing.T, value string) netip.Addr {
	t.Helper()

	addr, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatalf("ParseAddr() error = %v", err)
	}
	if !addr.Is4() {
		t.Fatalf("addr %s is not IPv4", value)
	}
	return addr
}

type recordingTCRunner struct {
	commands [][]string
}

func (r *recordingTCRunner) Run(_ context.Context, args ...string) error {
	copied := append([]string(nil), args...)
	r.commands = append(r.commands, copied)
	return nil
}

type missingQdiscTCRunner struct {
	commands [][]string
}

func (r *missingQdiscTCRunner) Run(_ context.Context, args ...string) error {
	copied := append([]string(nil), args...)
	r.commands = append(r.commands, copied)
	return fmt.Errorf(
		"tc %s: exit status 2: Error: Cannot find specified qdisc on specified device.",
		strings.Join(args, " "),
	)
}
