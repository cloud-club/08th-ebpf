//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip bpf ../memory.c -- -I /usr/include -O2 -Wall

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// EBPFManager는 eBPF 객체와 링크를 관리합니다.
type EBPFManager struct {
	objs bpfObjects
	l    link.Link
}

// NewEBPFManager는 eBPF 프로그램을 로드하고 초기화합니다.
func NewEBPFManager() (*EBPFManager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("메모리 잠금 제한 제거 실패: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("eBPF 객체 로드 실패: %w", err)
	}

	l, err := link.Tracepoint("kmem", "rss_stat", objs.TraceRssStat, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("tracepoint 연결 실패: %w", err)
	}

	fmt.Println("eBPF 프로그램이 성공적으로 로드 및 연결되었습니다.")
	return &EBPFManager{objs: objs, l: l}, nil
}

// StartMonitoring은 지정된 PID의 메모리 사용량 추적을 시작합니다.
func (m *EBPFManager) StartMonitoring(pid uint32) error {
	key := uint32(0)
	if err := m.objs.TargetPidMap.Put(key, &pid); err != nil {
		return fmt.Errorf("타겟 PID 맵 업데이트 실패: %w", err)
	}


	fmt.Printf("PID %d에 대한 메모리 모니터링을 시작합니다.\n", pid)
	return nil
}

func (m *EBPFManager) UpdateTargetPID(pid uint32) error {
	key := uint32(0)
	if err := m.objs.TargetPidMap.Put(key, &pid); err != nil {
		return fmt.Errorf("타겟 PID 맵 업데이트 실패: %w", err)
	}
	return nil
}

// GetPeakMemory는 추적된 프로세스의 최대 메모리 사용량을 반환합니다.
func (m *EBPFManager) GetPeakMemory(pid uint32) (int64, error) {
	var rss int64
	if err := m.objs.PeakRssBytes.Lookup(&pid, &rss); err != nil {
		return 0, fmt.Errorf("최대 메모리 사용량 조회 실패 for pid %d: %w", pid, err)
	}
	return rss, nil
}

// Close는 eBPF 링크와 객체를 닫습니다.
func (m *EBPFManager) Close() {
	if m.l != nil {
		m.l.Close()
	}
	if m.objs.TraceRssStat != nil {
		m.objs.Close()
	}
	fmt.Println("eBPF 리소스가 성공적으로 해제되었습니다.")
}

type DebugPIDs struct {
	EbpfPID   uint32
	TargetPID uint32
}

func (m *EBPFManager) GetDebugPIDs() (DebugPIDs, error) {
	var key uint32 = 0
	var debugVal struct {
		EbpfPID   uint32 `ebpf:"ebpf_pid"`
		TargetPID uint32 `ebpf:"target_pid"`
	}
	if err := m.objs.DebugPids.Lookup(&key, &debugVal); err != nil {
		return DebugPIDs{}, fmt.Errorf("디버그 PID 조회 실패: %w", err)
	}
	return DebugPIDs{EbpfPID: debugVal.EbpfPID, TargetPID: debugVal.TargetPID}, nil
}