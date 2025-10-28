package policy

import (
	"errors"
	"fmt"
	"sync"

	"ebpf-firewall/pkg/bpf"
	"ebpf-firewall/pkg/rule"
)

var (
	rules           []rule.Rule
	rulesMutex      sync.RWMutex
	defaultInbound  = rule.ActionDeny
	defaultOutbound = rule.ActionAllow
)

// 규칙 추가 - eBPF Map 기반으로 수정됨!
func AddRule(r *rule.Rule) error {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	// 1. eBPF Map에서 현재 규칙 가져오기
	mapRules, err := bpf.GetAllRules()
	if err != nil {
		return fmt.Errorf("규칙 조회 실패: %w", err)
	}

	// 2. 메모리 동기화 및 추가
	rules = mapRules
	rules = append(rules, *r)

	// 3. eBPF Map에 업데이트
	index := uint32(len(rules) - 1)
	if err := bpf.UpdateRule(index, r); err != nil {
		rules = rules[:len(rules)-1] // 롤백
		return err
	}

	return nil
}

// 규칙 삭제 - eBPF Map 기반으로 수정됨!
func RemoveRule(index int) error {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	// 1. eBPF Map에서 현재 규칙 목록 가져오기
	mapRules, err := bpf.GetAllRules()
	if err != nil {
		return fmt.Errorf("규칙 조회 실패: %w", err)
	}

	// 2. 인덱스 유효성 검사 (Map 기준)
	if index < 0 || index >= len(mapRules) {
		return errors.New("invalid rule index")
	}

	// 3. 메모리에서 규칙 제거
	rules = mapRules
	rules = append(rules[:index], rules[index+1:]...)

	// 4. eBPF Map 재구성 (전체 업데이트)
	if err := bpf.SyncAllRules(rules); err != nil {
		return fmt.Errorf("eBPF Map 동기화 실패: %w", err)
	}

	return nil
}

// 규칙 이동
func MoveRule(from, to int) error {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	// 1. eBPF Map에서 현재 규칙 목록 가져오기
	mapRules, err := bpf.GetAllRules()
	if err != nil {
		return fmt.Errorf("규칙 조회 실패: %w", err)
	}

	// 2. 인덱스 유효성 검사
	if from < 0 || from >= len(mapRules) || to < 0 || to >= len(mapRules) {
		return errors.New("invalid index")
	}

	// 3. 같은 위치면 아무것도 안함
	if from == to {
		return nil
	}

	// 4. 메모리 동기화
	rules = mapRules

	// 5. 단순 swap
	rules[from], rules[to] = rules[to], rules[from]

	// 6. eBPF Map 재구성
	if err := bpf.SyncAllRules(rules); err != nil {
		return fmt.Errorf("eBPF Map 동기화 실패: %w", err)
	}

	return nil
}

// 모든 규칙 삭제 - 에러 처리 수정됨!
func ResetRules() error {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	// 1. 메모리 초기화
	rules = []rule.Rule{}

	// 2. eBPF Map 초기화
	if err := bpf.ClearAllRules(); err != nil {
		return fmt.Errorf("eBPF Map 초기화 실패: %w", err)
	}

	return nil
}

// 규칙 목록 조회 - 이미 eBPF Map 기반!
func GetAllRules() []rule.Rule {
	rulesMutex.RLock()
	defer rulesMutex.RUnlock()

	// eBPF Map에서 직접 읽기 시도
	mapRules, err := bpf.GetAllRules()
	if err == nil {
		// Map에서 읽기 성공하면 메모리도 동기화
		rules = mapRules
		return mapRules
	}

	// eBPF가 로드되지 않았으면 메모리 배열 반환 (enable 전)
	result := make([]rule.Rule, len(rules))
	copy(result, rules)
	return result
}
