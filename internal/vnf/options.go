package vnf

import (
	"fmt"
	"strings"
	"time"
)

const (
	defaultRulesPath        = "/etc/nse-nat/rules.yaml"
	defaultRulePollInterval = 2 * time.Second
	defaultTCBinary         = "tc"
)

type Options struct {
	RulesPath        string
	RulePollInterval time.Duration
	TCBinary         string
}

func (o Options) withDefaults() Options {
	if strings.TrimSpace(o.RulesPath) == "" {
		o.RulesPath = defaultRulesPath
	}
	if o.RulePollInterval <= 0 {
		o.RulePollInterval = defaultRulePollInterval
	}
	if strings.TrimSpace(o.TCBinary) == "" {
		o.TCBinary = defaultTCBinary
	}
	return o
}

func (o Options) validate() error {
	if strings.TrimSpace(o.RulesPath) == "" {
		return fmt.Errorf("nat rules path is required")
	}
	if o.RulePollInterval <= 0 {
		return fmt.Errorf("nat rule poll interval must be positive")
	}
	if strings.TrimSpace(o.TCBinary) == "" {
		return fmt.Errorf("tc binary is required")
	}
	return nil
}
