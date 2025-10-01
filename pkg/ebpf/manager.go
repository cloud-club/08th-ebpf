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
	loader       *Loader       // eBPF 프로그램 로더
	updateTicker *time.Ticker  // 업데이트 티커
	stopChan     chan struct{} // 종료 신호 채널
}

func NewManager(cfg *config.Config, table *routing.Table) (*Manager, error) {
	loader, err := NewLoader(cfg)
	if err != nil {
		return nil, fmt.Errorf("eBPF 로더 생성 실패: %v", err)
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
		return fmt.Errorf("eBPF 프로그램 로드 실패: %v", err)
	}

	// 설정 파일에서 규칙 로드
	if len(m.config.RoutingRules) > 0 {
		err = m.table.LoadRules(m.config.RoutingRules)
		if err != nil {
			return fmt.Errorf("설정 파일 규칙 로드 실패: %v", err)
		}
	}

	// 규칙을 eBPF 맵에 업데이트
	activeRules := m.table.ListActiveRules()
	if len(activeRules) > 0 {
		err = m.loader.UpdateRules(activeRules)
		if err != nil {
			return fmt.Errorf("eBPF 규칙 업데이트 실패: %v", err)
		}
	} else {
		fmt.Println("활성화된 규칙이 없습니다.")
	}

	// 주기적 업데이트 시작
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

	return nil
}

func (m *Manager) periodicUpdate() {
	stats := m.table.GetStats()
	if stats.ActiveRules > 0 {
		fmt.Printf("규칙 상태 체크: %d개 활성 규칙 실행 중 (총 규칙: %d개)\n",
			stats.ActiveRules, stats.TotalRules)
	}
}

func (m *Manager) Stop() error {
	// 업데이트 루프 정지
	if m.updateTicker != nil {
		m.updateTicker.Stop()
	}
	close(m.stopChan)

	// eBPF 프로그램 언로드
	if m.loader.IsLoaded() {
		err := m.loader.UnloadProgram()
		if err != nil {
			fmt.Printf("경고: eBPF 프로그램 언로드 실패: %v\n", err)
		}
	}

	return nil
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
