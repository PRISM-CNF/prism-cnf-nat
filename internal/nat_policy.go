package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type NATMode string

const (
	NATModeStaticPortMap NATMode = "static_port_map"
	NATModeEmpty         NATMode = "empty"
)

type NATPolicy struct {
	Mode        NATMode
	VirtualIP   netip.Addr
	VirtualPort uint16
	BackendIP   netip.Addr
	BackendPort uint16
	Hash        string
}

type rawNATPolicy struct {
	Mode        string `yaml:"mode"`
	VirtualIP   string `yaml:"virtual_ip"`
	VirtualPort int    `yaml:"virtual_port"`
	BackendIP   string `yaml:"backend_ip"`
	BackendPort int    `yaml:"backend_port"`
}

func LoadNATPolicyFromFile(path string) (*NATPolicy, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("nat rules path is required")
	}

	rawData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read nat rules file: %w", err)
	}

	return ParseNATPolicy(rawData)
}

func ParseNATPolicy(rawData []byte) (*NATPolicy, error) {
	var raw rawNATPolicy
	if err := yaml.Unmarshal(rawData, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal nat rules YAML: %w", err)
	}

	mode, err := normalizeNATMode(raw.Mode)
	if err != nil {
		return nil, err
	}

	policy := &NATPolicy{
		Mode: mode,
		Hash: hashBytes(rawData),
	}
	if mode == NATModeEmpty {
		return policy, nil
	}

	virtualIP, err := parseIPv4Address(raw.VirtualIP, "virtual_ip")
	if err != nil {
		return nil, err
	}
	virtualPort, err := parsePort(raw.VirtualPort, "virtual_port")
	if err != nil {
		return nil, err
	}
	backendIP, err := parseIPv4Address(raw.BackendIP, "backend_ip")
	if err != nil {
		return nil, err
	}
	backendPort, err := parsePort(raw.BackendPort, "backend_port")
	if err != nil {
		return nil, err
	}
	if virtualIP == backendIP && virtualPort == backendPort {
		return nil, fmt.Errorf("virtual_ip/virtual_port and backend_ip/backend_port must differ")
	}

	policy.VirtualIP = virtualIP
	policy.VirtualPort = virtualPort
	policy.BackendIP = backendIP
	policy.BackendPort = backendPort
	return policy, nil
}

func normalizeNATMode(value string) (NATMode, error) {
	switch NATMode(strings.ToLower(strings.TrimSpace(value))) {
	case NATModeStaticPortMap:
		return NATModeStaticPortMap, nil
	case NATModeEmpty:
		return NATModeEmpty, nil
	default:
		return "", fmt.Errorf("invalid nat mode %q", value)
	}
}

func parseIPv4Address(raw string, fieldName string) (netip.Addr, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Addr{}, fmt.Errorf("%s must not be empty", fieldName)
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse %s %q: %w", fieldName, raw, err)
	}
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("%s must be an IPv4 address", fieldName)
	}
	return addr, nil
}

func parsePort(raw int, fieldName string) (uint16, error) {
	if raw < 1 || raw > 65535 {
		return 0, fmt.Errorf("%s %d is out of range", fieldName, raw)
	}
	return uint16(raw), nil
}

func hashBytes(rawData []byte) string {
	sum := sha256.Sum256(rawData)
	return hex.EncodeToString(sum[:])
}
