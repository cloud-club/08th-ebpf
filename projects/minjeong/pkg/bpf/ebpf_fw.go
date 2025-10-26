package bpf

import (
	"ebpf-firewall/pkg/rule"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux ebpf_fw ebpf_fw.c

const MaxRules = 1000 // C의 MAX_RULES와 동일해야 함

var (
	objs       ebpf_fwObjects
	program    *ebpf.Program
	links      []link.Link
	isAttached bool = false
)

// eBPF 프로그램 로드 및 TC에 연결
func LoadAndAttach() error {
	if isAttached {
		return fmt.Errorf("방화벽이 이미 활성화되어 있습니다")
	}

	// eBPF 오브젝트 로드
	if err := loadEbpf_fwObjects(&objs, nil); err != nil {
		return fmt.Errorf("eBPF 프로그램 로드 실패: %w", err)
	}

	// Program 저장
	program = objs.FirewallFilter

	// 네트워크 인터페이스 조회
	ifaces, err := net.Interfaces()
	if err != nil {
		objs.Close()
		return fmt.Errorf("네트워크 인터페이스 조회 실패: %w", err)
	}

	// 모든 활성 인터페이스에 연결 (loopback 제외)
	for _, iface := range ifaces {
		// loopback이거나 DOWN 상태인 인터페이스는 건너뛰기
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// TC ingress 연결
		lIngress, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   program,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			log.Printf("[경고] %s ingress hook 연결 실패: %v", iface.Name, err)
		} else {
			links = append(links, lIngress)
			log.Printf("[+] %s ingress hook 연결 성공", iface.Name)
		}

		// TC egress 연결
		lEgress, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   program,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			log.Printf("[경고] %s egress hook 연결 실패: %v", iface.Name, err)
		} else {
			links = append(links, lEgress)
			log.Printf("[+] %s egress hook 연결 성공", iface.Name)
		}
	}

	// 어떤 인터페이스에도 연결하지 못한 경우
	if len(links) == 0 {
		objs.Close()
		return fmt.Errorf("어떤 인터페이스에도 연결할 수 없습니다")
	}

	isAttached = true
	return nil
}

// eBPF 프로그램 분리 및 언로드
func Detach() error {
	if !isAttached {
		return fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
	}

	fmt.Println("[!] Detaching eBPF programs from interfaces...")

	// 모든 TC 링크 해제
	for _, l := range links {
		l.Close()
	}
	links = nil

	fmt.Println("[!] All interfaces detached.")

	// eBPF 오브젝트 닫기
	objs.Close()

	isAttached = false
	program = nil

	return nil
}

// 방화벽 상태 확인
func IsActive() bool {
	return isAttached
}

// 단일 규칙 업데이트
func UpdateRule(index uint32, r *rule.Rule) error {
	if !isAttached {
		return fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
	}

	// Go Rule을 C 구조체로 변환
	cRule := ebpf_fwFirewallRule{
		SrcIp:     r.SrcIP,
		DstIp:     r.DstIP,
		Port:      r.Port,
		Protocol:  uint8(r.Protocol),
		Direction: uint8(r.Direction),
		Action:    uint8(r.Action),
		Valid:     1,
	}

	// Map에 저장
	return objs.RulesArray.Put(index, cRule)
}

// 규칙 삭제 (무효화)
func DeleteRule(index uint32) error {
	if !isAttached {
		return fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
	}

	// Valid를 0으로 설정하여 무효화
	cRule := ebpf_fwFirewallRule{
		Valid: 0,
	}

	return objs.RulesArray.Put(index, cRule)
}

// 모든 규칙 동기화 (삭제/이동 시 사용)
func SyncAllRules(rules []rule.Rule) error {
	if !isAttached {
		return fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
	}

	// 1. 모든 슬롯 초기화 (valid = 0)
	emptyRule := ebpf_fwFirewallRule{Valid: 0}
	for i := uint32(0); i < MaxRules; i++ {
		if err := objs.RulesArray.Put(i, emptyRule); err != nil {
			return fmt.Errorf("규칙 초기화 실패 (index %d): %w", i, err)
		}
	}

	// 2. 실제 규칙 저장
	for i, r := range rules {
		if err := UpdateRule(uint32(i), &r); err != nil {
			return fmt.Errorf("규칙 동기화 실패 (index %d): %w", i, err)
		}
	}

	return nil
}

// 모든 규칙 삭제
func ClearAllRules() error {
	if !isAttached {
		return fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
	}

	emptyRule := ebpf_fwFirewallRule{Valid: 0}
	for i := uint32(0); i < MaxRules; i++ {
		if err := objs.RulesArray.Put(i, emptyRule); err != nil {
			return fmt.Errorf("규칙 삭제 실패 (index %d): %w", i, err)
		}
	}

	return nil
}

// 기본 정책 설정
func SetDefaultPolicy(direction rule.Direction, action rule.Action) error {
	if !isAttached {
		return fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
	}

	dirKey := uint32(direction)
	actionValue := uint8(action)

	return objs.DefaultPolicy.Put(dirKey, actionValue)
}

// 기본 정책 조회
func GetDefaultPolicy(direction rule.Direction) (rule.Action, error) {
	if !isAttached {
		return 0, fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
	}

	dirKey := uint32(direction)
	var action uint8

	if err := objs.DefaultPolicy.Lookup(dirKey, &action); err != nil {
		return 0, fmt.Errorf("기본 정책 조회 실패: %w", err)
	}

	return rule.Action(action), nil
}
