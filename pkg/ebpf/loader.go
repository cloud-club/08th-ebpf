package ebpf

import (
	"fmt"

	"ebpf-route/internal/config"
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

	fmt.Printf("시뮬레이션: eBPF 프로그램이 인터페이스 '%s'에 로드되었습니다\n", l.ifName)
	return nil
}

func (l *Loader) simulateUnload() error {
	fmt.Printf("시뮬레이션: eBPF 프로그램이 인터페이스 '%s'에서 언로드되었습니다\n", l.ifName)
	return nil
}

func (l *Loader) UpdateRules(rules []*config.RoutingRule) error {
	if !l.loaded {
		return fmt.Errorf("eBPF program is not loaded")
	}

	fmt.Printf("시뮬레이션: %d개 규칙 업데이트\n", len(rules))
	for _, rule := range rules {
		if rule.Enabled {
			srcIP := rule.SrcIP
			if srcIP == "" {
				srcIP = "*"
			}
			dstIP := rule.DstIP
			if dstIP == "" {
				dstIP = "*"
			}
			dstPort := ""
			if rule.DstPort > 0 {
				dstPort = fmt.Sprintf(":%d", rule.DstPort)
			}
			protocol := rule.Protocol
			if protocol == "" {
				protocol = "any"
			}

			fmt.Printf("  - 규칙 %d: %s %s -> %s%s (%s) [우선순위: %d]\n",
				rule.ID, rule.Action, srcIP, dstIP, dstPort, protocol, rule.Priority)
		}
	}
	return nil
}
