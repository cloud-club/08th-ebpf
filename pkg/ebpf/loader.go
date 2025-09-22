package ebpf

import (
	"ebpf-route/internal/config"
	"fmt"
)

type Loader struct {
	config *config.Config
	ifName string
	loaded bool
}

func NewLoader(cfg *config.Config) (*Loader, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	return &Loader{
		config: cfg,
		ifName: cfg.Network.Interface,
		loaded: false,
	}, nil
}

func (l *Loader) LoadProgram() error {
	if l.loaded {
		return fmt.Errorf("eBPF program is already loaded")
	}

	err := l.simulateLoad()
	if err != nil {
		return err
	}

	l.loaded = true
	return nil
}

func (l *Loader) UnloadProgram() error {
	if !l.loaded {
		return fmt.Errorf("no eBPF program is loaded")
	}

	err := l.simulateUnload()
	if err != nil {
		return err
	}

	l.loaded = false
	return nil
}

func (l *Loader) IsLoaded() bool {
	return l.loaded
}

func (l *Loader) GetInterface() string {
	return l.ifName
}

func (l *Loader) simulateLoad() error {
	if l.ifName == "" {
		return fmt.Errorf("network interface is not specified")
	}

	return nil
}

func (l *Loader) simulateUnload() error {
	return nil
}

func (l *Loader) UpdateRules(rules []*config.RoutingRule) error {
	if !l.loaded {
		return fmt.Errorf("eBPF program is not loaded")
	}

	for _, rule := range rules {
		if rule.Enabled {
			fmt.Printf("  - 규칙 %d: %s (%s -> %s)\n",
				rule.ID, rule.Action, rule.SrcIP, rule.DstIP)
		}
	}

	return nil
}
