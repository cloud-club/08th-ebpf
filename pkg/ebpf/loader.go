package ebpf

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"ebpf-route/internal/config"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Loader struct {
	config     *config.Config
	ifName     string
	loaded     bool
	collection *ebpf.Collection
	link       link.Link
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

	// eBPF 리소스 제한 해제
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %v", err)
	}

	// eBPF 프로그램 컴파일
	collection, err := l.compileAndLoadEBPF()
	if err != nil {
		return fmt.Errorf("failed to compile and load eBPF: %v", err)
	}

	// 인터페이스 이름을 인덱스로 변환
	ifIndex, err := l.getInterfaceIndex(l.ifName)
	if err != nil {
		collection.Close()
		return fmt.Errorf("failed to get interface index: %v", err)
	}

	// XDP 프로그램을 네트워크 인터페이스에 연결
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   collection.Programs["xdp_router_main"],
		Interface: ifIndex,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		collection.Close()
		return fmt.Errorf("failed to attach XDP program: %v", err)
	}

	l.collection = collection
	l.link = xdpLink
	l.loaded = true

	fmt.Printf("실제 eBPF 프로그램이 인터페이스 '%s'에 로드되었습니다\n", l.ifName)
	return nil
}

func (l *Loader) UnloadProgram() error {
	if !l.loaded {
		return fmt.Errorf("no eBPF program is loaded")
	}

	// XDP 링크 해제
	if l.link != nil {
		if err := l.link.Close(); err != nil {
			fmt.Printf("경고: XDP 링크 해제 실패: %v\n", err)
		}
	}

	// eBPF 컬렉션 해제
	if l.collection != nil {
		l.collection.Close()
	}

	l.loaded = false
	fmt.Printf("실제 eBPF 프로그램이 인터페이스 '%s'에서 언로드되었습니다\n", l.ifName)
	return nil
}

func (l *Loader) IsLoaded() bool {
	return l.loaded
}

func (l *Loader) GetInterface() string {
	return l.ifName
}

func (l *Loader) compileAndLoadEBPF() (*ebpf.Collection, error) {
	// eBPF 프로그램 컴파일
	objFile, err := l.compileEBPF()
	if err != nil {
		return nil, fmt.Errorf("failed to compile eBPF: %v", err)
	}
	defer os.Remove(objFile) // 임시 파일 삭제

	// 컴파일된 eBPF 프로그램 로드
	spec, err := ebpf.LoadCollectionSpec(objFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection spec: %v", err)
	}

	// eBPF 컬렉션 생성
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %v", err)
	}

	return collection, nil
}

func (l *Loader) compileEBPF() (string, error) {
	// 임시 파일 생성
	tmpFile, err := os.CreateTemp("", "xdp_router_*.o")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}
	tmpFile.Close()

	// clang 명령어 구성
	clangArgs := []string{
		"-O2", "-g", "-Wall", "-Werror",
		"-target", "bpf",
		"-c", "bpf/xdp_router.c",
		"-o", tmpFile.Name(),
		"-I", "bpf",
		"-I", "/usr/include",
		"-I", "/usr/include/x86_64-linux-gnu",
		"-I", "/usr/include/asm-generic",
		"-D__BPF_TRACING__",
		"-D__TARGET_ARCH_x86",
	}

	// clang 실행
	cmd := exec.Command("clang", clangArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("clang compilation failed: %v", err)
	}

	return tmpFile.Name(), nil
}

func (l *Loader) UpdateRules(rules []*config.RoutingRule) error {
	if !l.loaded {
		return fmt.Errorf("eBPF program is not loaded")
	}

	if l.collection == nil {
		return fmt.Errorf("eBPF collection is not loaded")
	}

	// rules_map 가져오기
	rulesMap := l.collection.Maps["rules_map"]
	if rulesMap == nil {
		return fmt.Errorf("rules_map not found in eBPF collection")
	}

	fmt.Printf("실제 eBPF 맵에 %d개 규칙 업데이트\n", len(rules))

	// 기존 규칙 삭제 (ID 1-100)
	for i := uint32(1); i <= 100; i++ {
		rulesMap.Delete(i)
	}

	// 새 규칙 추가
	for _, rule := range rules {
		if rule.Enabled {
			// Go 구조체를 C 구조체로 변환
			ebpfRule := l.convertToEBPFRule(rule)

			// eBPF 맵에 규칙 추가
			if err := rulesMap.Put(uint32(rule.ID), ebpfRule); err != nil {
				fmt.Printf("경고: 규칙 %d 추가 실패: %v\n", rule.ID, err)
				continue
			}

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

// eBPF 규칙 구조체 (C 구조체와 일치)
type EBPFRule struct {
	ID        uint32
	SrcIP     uint32
	DstIP     uint32
	SrcIPMask uint32
	DstIPMask uint32
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Action    uint8
	Priority  uint8
	Enabled   uint8
}

func (l *Loader) convertToEBPFRule(rule *config.RoutingRule) EBPFRule {
	ebpfRule := EBPFRule{
		ID:       uint32(rule.ID),
		SrcPort:  uint16(0), // TODO: src_port 지원
		DstPort:  uint16(rule.DstPort),
		Priority: uint8(rule.Priority),
		Enabled:  uint8(1),
	}

	// 액션 변환
	switch strings.ToLower(rule.Action) {
	case "drop":
		ebpfRule.Action = 0
	case "pass":
		ebpfRule.Action = 1
	case "redirect":
		ebpfRule.Action = 2
	default:
		ebpfRule.Action = 1 // 기본값: pass
	}

	// 프로토콜 변환
	switch strings.ToLower(rule.Protocol) {
	case "tcp":
		ebpfRule.Protocol = 6
	case "udp":
		ebpfRule.Protocol = 17
	case "icmp":
		ebpfRule.Protocol = 1
	default:
		ebpfRule.Protocol = 0 // any
	}

	// IP 주소 변환 (TODO: 실제 IP 파싱 구현)
	// 현재는 간단한 예시
	if rule.SrcIP != "" {
		// CIDR 파싱 및 변환 필요
		ebpfRule.SrcIP = 0xC0A80100     // 192.168.1.0 예시
		ebpfRule.SrcIPMask = 0xFFFFFF00 // /24 예시
	}

	if rule.DstIP != "" {
		// CIDR 파싱 및 변환 필요
		ebpfRule.DstIP = 0xC0A80100     // 192.168.1.0 예시
		ebpfRule.DstIPMask = 0xFFFFFF00 // /24 예시
	}

	return ebpfRule
}

func (l *Loader) getInterfaceIndex(ifName string) (int, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return 0, fmt.Errorf("interface %s not found: %v", ifName, err)
	}
	return iface.Index, nil
}
