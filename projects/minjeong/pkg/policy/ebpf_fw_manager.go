package policy

import (
	"errors"
	"sync"

	"ebpf-firewall/pkg/bpf"
	"ebpf-firewall/pkg/rule"
	// "ebpf-firewall/pkg/storage"
)

var (
	rules      []rule.Rule
	rulesMutex sync.RWMutex

	defaultInbound  = rule.ActionDeny
	defaultOutbound = rule.ActionAllow
)

// 규칙 추가
func AddRule(r *rule.Rule) error {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	// 1. 검증 (선택적)
	// if err := ValidateRule(r); err != nil {
	// 	return err
	// }

	// 2. 중복 체크 (선택적)
	// if isDuplicate(r) { return errors.New("duplicate rule") }

	// 3. 메모리 배열에 추가
	rules = append(rules, *r)

	// 4. eBPF Map 업데이트
	index := uint32(len(rules) - 1)
	if err := bpf.UpdateRule(index, r); err != nil {
		rules = rules[:len(rules)-1] // 롤백
		return err
	}

	// 5. JSON 파일 저장
	// if err := storage.SaveRules(rules); err != nil {
	// 	// 경고만 하고 계속 진행 (Map은 이미 업데이트됨)
	// 	fmt.Printf("Warning: failed to save to JSON: %v\n", err)
	// }

	return nil
}

// 규칙 삭제
func RemoveRule(index int) error {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	if index < 0 || index >= len(rules) {
		return errors.New("invalid rule index")
	}

	// 1. 메모리에서 삭제
	removedRule := rules[index]
	rules = append(rules[:index], rules[index+1:]...)

	// 2. eBPF Map 재구성 (전체 업데이트)
	if err := bpf.SyncAllRules(rules); err != nil {
		// 롤백
		rules = append(rules[:index], append([]rule.Rule{removedRule}, rules[index:]...)...)
		return err
	}

	// 3. JSON 저장
	// storage.SaveRules(rules)

	return nil
}

// 규칙 이동
func MoveRule(from, to int) error {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	if from < 0 || from >= len(rules) || to < 0 || to >= len(rules) {
		return errors.New("invalid index")
	}

	// 1. 메모리에서 순서 변경
	r := rules[from]
	rules = append(rules[:from], rules[from+1:]...) // from 제거

	// to 위치에 삽입
	rules = append(rules[:to], append([]rule.Rule{r}, rules[to:]...)...)

	// 2. eBPF Map 재구성
	if err := bpf.SyncAllRules(rules); err != nil {
		// 롤백 (복잡하므로 생략)
		return err
	}

	// 3. JSON 저장
	// storage.SaveRules(rules)

	return nil
}

// 모든 규칙 삭제
func ResetRules() error {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	rules = []rule.Rule{}

	// eBPF Map 초기화
	bpf.ClearAllRules()

	// JSON 저장
	// storage.SaveRules(rules)

	return nil
}

// 규칙 목록 조회
func GetAllRules() []rule.Rule {
	rulesMutex.RLock()
	defer rulesMutex.RUnlock()

	result := make([]rule.Rule, len(rules))
	copy(result, rules)
	return result
}
