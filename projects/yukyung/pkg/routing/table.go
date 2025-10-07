package routing

import (
	"ebpf-route/internal/config"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Table은 라우팅 규칙 테이블을 관리합니다
type Table struct {
	mu       sync.RWMutex
	rules    map[int]*config.RoutingRule
	maxRules int
	stats    *TableStats
}

// TableStats는 테이블 통계 정보를 담습니다
type TableStats struct {
	TotalRules  int       `json:"total_rules"`
	ActiveRules int       `json:"active_rules"`
	LastUpdated time.Time `json:"last_updated"`
	PacketCount uint64    `json:"packet_count"`
	MatchCount  uint64    `json:"match_count"`
	DropCount   uint64    `json:"drop_count"`
	PassCount   uint64    `json:"pass_count"`
}

// NewTable은 새로운 라우팅 테이블을 생성합니다
func NewTable(maxRules int) *Table {
	return &Table{
		rules:    make(map[int]*config.RoutingRule),
		maxRules: maxRules,
		stats: &TableStats{
			LastUpdated: time.Now(),
		},
	}
}

// AddRule은 새로운 규칙을 추가합니다
func (t *Table) AddRule(rule *config.RoutingRule) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.rules) >= t.maxRules {
		return fmt.Errorf("최대 규칙 수를 초과했습니다: %d", t.maxRules)
	}

	if _, exists := t.rules[rule.ID]; exists {
		return fmt.Errorf("ID %d인 규칙이 이미 존재합니다", rule.ID)
	}

	// 규칙 복사본 저장
	ruleCopy := *rule
	t.rules[rule.ID] = &ruleCopy
	t.updateStats()

	return nil
}

// RemoveRule은 규칙을 제거합니다
func (t *Table) RemoveRule(id int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.rules[id]; !exists {
		return fmt.Errorf("ID %d인 규칙을 찾을 수 없습니다", id)
	}

	delete(t.rules, id)
	t.updateStats()

	return nil
}

// GetRule은 특정 ID의 규칙을 반환합니다
func (t *Table) GetRules(id int) (*config.RoutingRule, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	rule, exists := t.rules[id]
	if !exists {
		return nil, fmt.Errorf("ID %d인 규칙을 찾을 수 없습니다", id)
	}

	// 복사본 반환
	ruleCopy := *rule
	return &ruleCopy, nil
}

// ListActiveRules는 활성화된 규칙을 우선순위 순으로 반환합니다
func (t *Table) ListActiveRules() []*config.RoutingRule {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var rules []*config.RoutingRule
	for _, rule := range t.rules {
		if rule.Enabled {
			ruleCopy := *rule
			rules = append(rules, &ruleCopy)
		}
	}

	// 우선순위 순으로 정렬
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		// 우선순위가 같으면 ID 순으로
		return rules[i].ID < rules[j].ID
	})

	return rules
}

// EnableRule은 규칙을 활성화합니다
func (t *Table) EnableRule(id int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	rule, exists := t.rules[id]
	if !exists {
		return fmt.Errorf("ID %d인 규칙을 찾을 수 없습니다", id)
	}

	rule.Enabled = true
	t.updateStats()

	fmt.Printf("규칙 활성화됨: ID=%d\n", id)
	return nil
}

// DisableRule은 규칙을 비활성화합니다
func (t *Table) DisableRule(id int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	rule, exists := t.rules[id]
	if !exists {
		return fmt.Errorf("ID %d인 규칙을 찾을 수 없습니다", id)
	}

	rule.Enabled = false
	t.updateStats()

	fmt.Printf("규칙 비활성화됨: ID=%d\n", id)
	return nil
}

// LoadRules는 여러 규칙을 한 번에 로드합니다
// 초기 규칙 로드 시 사용
func (t *Table) LoadRules(rules []*config.RoutingRule) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// 기존 규칙 초기화
	t.rules = make(map[int]*config.RoutingRule)

	for _, rule := range rules {
		if len(t.rules) >= t.maxRules {
			return fmt.Errorf("최대 규칙 수를 초과했습니다 (%d)", t.maxRules)
		}

		if _, exists := t.rules[rule.ID]; exists {
			return fmt.Errorf("중복된 규칙 ID: %d", rule.ID)
		}

		// 규칙 복사본 저장
		ruleCopy := *rule
		t.rules[rule.ID] = &ruleCopy
	}

	t.updateStats()
	fmt.Printf("총 %d개 규칙이 로드되었습니다\n", len(t.rules))
	return nil
}

// GetStats는 테이블 통계를 반환합니다
func (t *Table) GetStats() *TableStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// 통계 복사본 반환
	stats := *t.stats
	return &stats
}

// updateStats는 내부 통계를 업데이트합니다
func (t *Table) updateStats() {
	totalRules := len(t.rules)
	activeRules := 0

	for _, rule := range t.rules {
		if rule.Enabled {
			activeRules++
		}
	}

	t.stats.TotalRules = totalRules
	t.stats.ActiveRules = activeRules
	t.stats.LastUpdated = time.Now()
}
