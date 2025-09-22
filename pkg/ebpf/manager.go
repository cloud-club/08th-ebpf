package ebpf

import (
	"fmt"
	"time"

	"ebpf-route/internal/config"
	"ebpf-route/pkg/routing"
)

type Manager struct {
	config       *config.Config
	table        *routing.Table
	loader       *Loader
	updateTicker *time.Ticker
	stopChan     chan struct{}
}

func NewManager(cfg *config.Config, table *routing.Table) (*Manager, error) {
	loader, err := NewLoader(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF loader: %v", err)
	}

	return &Manager{
		config:   cfg,
		table:    table,
		loader:   loader,
		stopChan: make(chan struct{}),
	}, nil
}

func (m *Manager) Start() error {
	// eBPF 프로그램 로드
	err := m.loader.LoadProgram()
	if err != nil {
		return fmt.Errorf("failed to load eBPF program: %v", err)
	}

	// 규칙을 eBPF 맵에 업데이트
	activeRules := m.table.ListActiveRules()
	err = m.loader.UpdateRules(activeRules)
	if err != nil {
		return fmt.Errorf("failed to update eBPF rules: %v", err)
	}

	// 주기적 업데이트 시작
	m.startUpdateLoop()

	return nil
}

func (m *Manager) Stop() error {
	// 업데이트 루프 정지
	m.stopUpdateLoop()

	// eBPF 프로그램 언로드
	if m.loader.IsLoaded() {
		err := m.loader.UnloadProgram()
		if err != nil {
			fmt.Printf("경고: eBPF 프로그램 언로드 실패: %v\n", err)
		}
	}

	return nil
}

func (m *Manager) startUpdateLoop() {
	m.updateTicker = time.NewTicker(m.config.Router.UpdateInterval)

	go func() {
		for {
			select {
			case <-m.updateTicker.C:
				m.periodicUpdate()
			case <-m.stopChan:
				return
			}
		}
	}()
}

func (m *Manager) stopUpdateLoop() {
	if m.updateTicker != nil {
		m.updateTicker.Stop()
	}

	close(m.stopChan)
}

func (m *Manager) periodicUpdate() {
	stats := m.table.GetStats()
	if stats.ActiveRules > 0 {
		fmt.Printf("규칙 상태 체크: %d개 활성 규칙 실행 중 (패킷 처리: %d개)\n",
			stats.ActiveRules, stats.PacketCount)
	}

	// TODO: eBPF 맵에서 통계 정보 수집
	// TODO: 규칙 변경사항이 있으면 eBPF 맵 업데이트
}

func (m *Manager) AddRule(rule *config.RoutingRule) error {
	err := m.table.AddRule(rule)
	if err != nil {
		return err
	}

	if m.loader.IsLoaded() {
		activeRules := m.table.ListActiveRules()
		return m.loader.UpdateRules(activeRules)
	}

	return nil
}

func (m *Manager) RemoveRule(id int) error {
	err := m.table.RemoveRule(id)
	if err != nil {
		return err
	}

	if m.loader.IsLoaded() {
		activeRules := m.table.ListActiveRules()
		return m.loader.UpdateRules(activeRules)
	}

	return nil
}
