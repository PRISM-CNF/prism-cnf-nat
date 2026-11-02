package vnf

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/networkservicemesh/sdk/pkg/tools/log"

	"nse-ovs-nat/internal"
	"nse-ovs-nat/internal/processor"
)

const (
	tcForwardChain        = 10
	tcReverseChain        = 20
	tcConnectionMark      = "1"
	tcConnectionMarkMatch = "1/0xffffffff"

	tcPrefForwardLookupTCP    = 100
	tcPrefForwardCommitTCP    = 110
	tcPrefForwardTranslateTCP = 111
	tcPrefReverseLookupTCP    = 200
	tcPrefReverseTranslateTCP = 210

	tcPrefForwardLookupUDP    = 120
	tcPrefForwardCommitUDP    = 130
	tcPrefForwardTranslateUDP = 131
	tcPrefReverseLookupUDP    = 220
	tcPrefReverseTranslateUDP = 230
)

type tcRunner interface {
	Run(ctx context.Context, args ...string) error
}

type execTCRunner struct {
	binary string
}

type watchedRuleSession struct {
	runner  tcRunner
	options Options
	flow    FlowInfo
	state   *SessionState
	logCtx  context.Context
	closeCh chan struct{}
	doneCh  chan struct{}

	closeOnce sync.Once
	mu        sync.Mutex
	active    *internal.NATPolicy
}

func NewNoopRuleInstaller() RuleInstaller {
	return RuleInstallerFunc(func(_ context.Context, _ *SessionContext) (processor.Session, error) {
		return processor.CloseFunc(func(context.Context) error {
			return nil
		}), nil
	})
}

func DefaultRuleInstaller(options Options) RuleInstaller {
	options = options.withDefaults()
	return RuleInstallerFunc(func(ctx context.Context, sessionCtx *SessionContext) (processor.Session, error) {
		return installTrafficRulesFromPath(ctx, sessionCtx, options, &execTCRunner{binary: options.TCBinary})
	})
}

// installTrafficRules is the first customization point for future VNFs.
// Use it to install ACLs, conntrack rules, route entries, OVS flows, or NAT state.
// Persist generated rule IDs or handles in sessionCtx.State() for later phases.
func installTrafficRulesFromPath(ctx context.Context, sessionCtx *SessionContext, options Options, runner tcRunner) (processor.Session, error) {
	if sessionCtx == nil {
		return nil, fmt.Errorf("session context is required")
	}
	if runner == nil {
		return nil, fmt.Errorf("tc runner is required")
	}

	options = options.withDefaults()
	if err := options.validate(); err != nil {
		return nil, err
	}

	logCtx := log.WithLog(context.Background(), log.FromContext(ctx))
	session := &watchedRuleSession{
		runner:  runner,
		options: options,
		flow:    sessionCtx.Flow(),
		state:   sessionCtx.State(),
		logCtx:  logCtx,
		closeCh: make(chan struct{}),
		doneCh:  make(chan struct{}),
	}

	policy, err := session.loadPolicy()
	if err != nil {
		return nil, err
	}
	if err := session.applyPolicy(ctx, policy); err != nil {
		return nil, err
	}

	go session.watchPolicy()
	return session, nil
}

func (r *execTCRunner) Run(ctx context.Context, args ...string) error {
	if r == nil {
		return fmt.Errorf("tc runner is required")
	}
	if strings.TrimSpace(r.binary) == "" {
		return fmt.Errorf("tc binary is required")
	}

	output, err := exec.CommandContext(ctx, r.binary, args...).CombinedOutput()
	if err == nil {
		return nil
	}

	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return fmt.Errorf("%s %s: %w", r.binary, strings.Join(args, " "), err)
	}
	return fmt.Errorf("%s %s: %w: %s", r.binary, strings.Join(args, " "), err, trimmed)
}

func (s *watchedRuleSession) loadPolicy() (*internal.NATPolicy, error) {
	policy, err := internal.LoadNATPolicyFromFile(s.options.RulesPath)
	if err != nil {
		return nil, fmt.Errorf("load nat rules from %s: %w", s.options.RulesPath, err)
	}
	return policy, nil
}

func (s *watchedRuleSession) applyPolicy(ctx context.Context, policy *internal.NATPolicy) error {
	if policy == nil {
		return fmt.Errorf("nat policy is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := cleanupTCState(ctx, s.runner, s.flow); err != nil {
		return err
	}
	if policy.Mode == internal.NATModeStaticPortMap {
		if err := applyStaticPortMapPolicy(ctx, s.runner, s.flow, policy); err != nil {
			return err
		}
	}

	s.active = policy
	storePolicyState(s.state, s.options, policy)

	log.FromContext(ctx).Infof(
		"applied nat policy mode=%s virtual=%s:%d backend=%s:%d ct_zone=%d ingress=%s egress=%s",
		policy.Mode,
		describePolicyAddr(policy.VirtualIP),
		policy.VirtualPort,
		describePolicyAddr(policy.BackendIP),
		policy.BackendPort,
		connectionTrackingZone(s.flow.ConnectionID),
		s.flow.IngressInterface,
		s.flow.EgressInterface,
	)

	return nil
}

func (s *watchedRuleSession) watchPolicy() {
	ticker := time.NewTicker(s.options.RulePollInterval)
	defer ticker.Stop()
	defer close(s.doneCh)

	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
			policy, err := s.loadPolicy()
			if err != nil {
				log.FromContext(s.logCtx).Errorf("reload nat rules failed: %v", err)
				continue
			}
			if s.samePolicyHash(policy.Hash) {
				continue
			}
			if err := s.applyPolicy(s.logCtx, policy); err != nil {
				log.FromContext(s.logCtx).Errorf("apply reloaded nat rules failed: %v", err)
			}
		}
	}
}

func (s *watchedRuleSession) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}

	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
	<-s.doneCh

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != nil {
		s.state.Delete(StateKeyNATMode)
		s.state.Delete(StateKeyNATRuleHash)
		s.state.Delete(StateKeyNATRulesPath)
		s.state.Delete(StateKeyNATVirtualIP)
		s.state.Delete(StateKeyNATVirtualPort)
		s.state.Delete(StateKeyNATBackendIP)
		s.state.Delete(StateKeyNATBackendPort)
	}

	return cleanupTCState(ctx, s.runner, s.flow)
}

func (s *watchedRuleSession) samePolicyHash(hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.active != nil && s.active.Hash == hash
}

func applyStaticPortMapPolicy(ctx context.Context, runner tcRunner, flow FlowInfo, policy *internal.NATPolicy) error {
	if runner == nil {
		return fmt.Errorf("tc runner is required")
	}
	if policy == nil {
		return fmt.Errorf("nat policy is required")
	}
	if flow.IngressInterface == "" || flow.EgressInterface == "" {
		return fmt.Errorf("both ingress and egress interfaces are required")
	}

	for _, iface := range []string{flow.IngressInterface, flow.EgressInterface} {
		if err := ensureClsact(ctx, runner, iface); err != nil {
			return err
		}
	}

	for _, command := range renderStaticPortMapCommands(flow, policy) {
		if err := runner.Run(ctx, command...); err != nil {
			return err
		}
	}

	return nil
}

func renderStaticPortMapCommands(flow FlowInfo, policy *internal.NATPolicy) [][]string {
	if policy == nil {
		return nil
	}

	zone := connectionTrackingZone(flow.ConnectionID)
	virtualIP := policy.VirtualIP.String()
	virtualPort := fmt.Sprintf("%d", policy.VirtualPort)
	backendIP := policy.BackendIP.String()
	backendPort := fmt.Sprintf("%d", policy.BackendPort)

	commands := make([][]string, 0, 10)
	commands = append(commands, renderStaticPortMapCommandsForProtocol(
		flow,
		"tcp",
		tcRulePrefs{
			forwardLookup:    tcPrefForwardLookupTCP,
			forwardCommit:    tcPrefForwardCommitTCP,
			forwardTranslate: tcPrefForwardTranslateTCP,
			reverseLookup:    tcPrefReverseLookupTCP,
			reverseTranslate: tcPrefReverseTranslateTCP,
		},
		virtualIP,
		virtualPort,
		backendIP,
		backendPort,
		zone,
	)...)
	commands = append(commands, renderStaticPortMapCommandsForProtocol(
		flow,
		"udp",
		tcRulePrefs{
			forwardLookup:    tcPrefForwardLookupUDP,
			forwardCommit:    tcPrefForwardCommitUDP,
			forwardTranslate: tcPrefForwardTranslateUDP,
			reverseLookup:    tcPrefReverseLookupUDP,
			reverseTranslate: tcPrefReverseTranslateUDP,
		},
		virtualIP,
		virtualPort,
		backendIP,
		backendPort,
		zone,
	)...)
	return commands
}

type tcRulePrefs struct {
	forwardLookup    int
	forwardCommit    int
	forwardTranslate int
	reverseLookup    int
	reverseTranslate int
}

func renderStaticPortMapCommandsForProtocol(
	flow FlowInfo,
	ipProto string,
	prefs tcRulePrefs,
	virtualIP string,
	virtualPort string,
	backendIP string,
	backendPort string,
	zone int,
) [][]string {
	return [][]string{
		renderCTLookupCommand(flow.IngressInterface, tcForwardChain, prefs.forwardLookup, ipProto, "dst_ip", virtualIP, "dst_port", virtualPort, zone),
		renderCTCommitNATCommand(flow.IngressInterface, tcForwardChain, prefs.forwardCommit, ipProto, virtualIP, virtualPort, zone, backendIP, backendPort),
		renderCTTranslateCommand(flow.IngressInterface, tcForwardChain, prefs.forwardTranslate, ipProto, "", "", zone, "+trk+est"),
		renderCTLookupCommand(flow.EgressInterface, tcReverseChain, prefs.reverseLookup, ipProto, "src_ip", backendIP, "src_port", backendPort, zone),
		renderCTTranslateCommand(flow.EgressInterface, tcReverseChain, prefs.reverseTranslate, ipProto, backendIP, backendPort, zone, "+trk+rpl"),
	}
}

func renderCTLookupCommand(iface string, chain, pref int, ipProto string, ipField, matchIP, portField, matchPort string, zone int) []string {
	return []string{
		"filter", "replace",
		"dev", iface,
		"ingress",
		"chain", "0",
		"pref", fmt.Sprintf("%d", pref),
		"protocol", "ip",
		"flower", "skip_hw",
		"ip_proto", ipProto,
		ipField, matchIP,
		portField, matchPort,
		"ct_state", "-trk",
		"action", "ct", "zone", fmt.Sprintf("%d", zone),
		"pipe",
		"action", "goto", "chain", fmt.Sprintf("%d", chain),
	}
}

func renderCTCommitNATCommand(iface string, chain, pref int, ipProto, matchIP, matchPort string, zone int, backendIP, backendPort string) []string {
	return []string{
		"filter", "replace",
		"dev", iface,
		"ingress",
		"chain", fmt.Sprintf("%d", chain),
		"pref", fmt.Sprintf("%d", pref),
		"protocol", "ip",
		"flower", "skip_hw",
		"ip_proto", ipProto,
		"dst_ip", matchIP,
		"dst_port", matchPort,
		"ct_zone", fmt.Sprintf("%d", zone),
		"ct_state", "+trk+new",
		"action", "ct", "commit",
		"zone", fmt.Sprintf("%d", zone),
		"mark", tcConnectionMark,
		"nat", "dst", "addr", backendIP,
		"port", backendPort,
	}
}

func renderCTTranslateCommand(iface string, chain, pref int, ipProto, matchIP, matchPort string, zone int, ctState string) []string {
	command := []string{
		"filter", "replace",
		"dev", iface,
		"ingress",
		"chain", fmt.Sprintf("%d", chain),
		"pref", fmt.Sprintf("%d", pref),
		"protocol", "ip",
		"flower", "skip_hw",
		"ip_proto", ipProto,
	}
	if strings.TrimSpace(matchIP) != "" {
		command = append(command, "src_ip", matchIP)
	}
	if strings.TrimSpace(matchPort) != "" {
		command = append(command, "src_port", matchPort)
	}
	command = append(
		command,
		"ct_zone", fmt.Sprintf("%d", zone),
		"ct_mark", tcConnectionMarkMatch,
		"ct_state", ctState,
		"action", "ct", "nat", "zone", fmt.Sprintf("%d", zone),
	)
	return command
}

func connectionTrackingZone(connectionID string) int {
	trimmed := strings.TrimSpace(connectionID)
	if trimmed == "" {
		return 1
	}

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(trimmed))
	return int(hasher.Sum32()%65535) + 1
}

func ensureClsact(ctx context.Context, runner tcRunner, iface string) error {
	err := runner.Run(ctx, "qdisc", "add", "dev", iface, "clsact")
	if isExistingTCObjectError(err) {
		return nil
	}
	return err
}

func cleanupTCState(ctx context.Context, runner tcRunner, flow FlowInfo) error {
	if runner == nil {
		return fmt.Errorf("tc runner is required")
	}

	var errs []error
	for _, iface := range []string{flow.IngressInterface, flow.EgressInterface} {
		if strings.TrimSpace(iface) == "" {
			continue
		}
		err := runner.Run(ctx, "qdisc", "delete", "dev", iface, "clsact")
		if isMissingTCObjectError(err) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func storePolicyState(state *SessionState, options Options, policy *internal.NATPolicy) {
	if state == nil || policy == nil {
		return
	}

	state.Store(StateKeyNATRulesPath, options.RulesPath)
	state.Store(StateKeyNATMode, string(policy.Mode))
	state.Store(StateKeyNATRuleHash, policy.Hash)

	if policy.Mode == internal.NATModeStaticPortMap {
		state.Store(StateKeyNATVirtualIP, policy.VirtualIP.String())
		state.Store(StateKeyNATVirtualPort, fmt.Sprintf("%d", policy.VirtualPort))
		state.Store(StateKeyNATBackendIP, policy.BackendIP.String())
		state.Store(StateKeyNATBackendPort, fmt.Sprintf("%d", policy.BackendPort))
		return
	}

	state.Delete(StateKeyNATVirtualIP)
	state.Delete(StateKeyNATVirtualPort)
	state.Delete(StateKeyNATBackendIP)
	state.Delete(StateKeyNATBackendPort)
}

func describePolicyAddr(addr fmt.Stringer) string {
	if addr == nil {
		return "-"
	}
	return addr.String()
}

func isExistingTCObjectError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "file exists")
}

func isMissingTCObjectError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such file or directory") ||
		strings.Contains(message, "cannot delete qdisc with handle of zero") ||
		strings.Contains(message, "cannot find specified qdisc on specified device")
}
