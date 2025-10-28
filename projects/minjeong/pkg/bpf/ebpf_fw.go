package bpf

import (
	"ebpf-firewall/pkg/rule"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux ebpf_fw ebpf_fw.c

const MaxRules = 30
const stateFilePath = "/var/run/ebpfw.state"
const bpfMountPoint = "/sys/fs/bpf"

var (
	objs       ebpf_fwObjects
	program    *ebpf.Program
	isAttached bool = false
)

func ensureBPFFS() error {
	var stat unix.Statfs_t
	if err := unix.Statfs(bpfMountPoint, &stat); err == nil {
		if stat.Type == 0xcafe4a11 {
			return nil
		}
	}

	if err := os.MkdirAll(bpfMountPoint, 0755); err != nil {
		return fmt.Errorf("BPF 마운트 포인트 생성 실패: %w", err)
	}

	if err := unix.Mount("bpffs", bpfMountPoint, "bpf", 0, ""); err != nil {
		if err != unix.EBUSY {
			return fmt.Errorf("BPF 파일시스템 마운트 실패: %w", err)
		}
	} else {
		log.Printf("[+] BPF 파일시스템을 %s에 마운트했습니다", bpfMountPoint)
	}

	return nil
}

// TC를 사용한 eBPF attach (WSL2 호환)
func LoadAndAttach() error {
	if isAttached {
		return fmt.Errorf("방화벽이 이미 활성화되어 있습니다")
	}

	if err := ensureBPFFS(); err != nil {
		return err
	}

	if err := loadEbpf_fwObjects(&objs, nil); err != nil {
		return fmt.Errorf("eBPF 프로그램 로드 실패: %w", err)
	}

	// Map pin
	pinPath := "/sys/fs/bpf/ebpfw_rules"
	os.Remove(pinPath)
	if err := objs.RulesArray.Pin(pinPath); err != nil {
		objs.Close()
		return fmt.Errorf("Map pin 실패: %w", err)
	}

	policyPinPath := "/sys/fs/bpf/ebpfw_policy"
	os.Remove(policyPinPath)
	if err := objs.DefaultPolicy.Pin(policyPinPath); err != nil {
		objs.Close()
		return fmt.Errorf("Policy map pin 실패: %w", err)
	}

	// 기본 정책 설정
	var inboundKey uint32 = 0
	var outboundKey uint32 = 1
	var inboundAction uint8 = 0  // deny
	var outboundAction uint8 = 1 // allow
	_ = objs.DefaultPolicy.Put(inboundKey, inboundAction)
	_ = objs.DefaultPolicy.Put(outboundKey, outboundAction)

	program = objs.FirewallFilter

	// 모든 네트워크 인터페이스에 TC 필터 추가
	ifaces, err := net.Interfaces()
	if err != nil {
		objs.Close()
		return fmt.Errorf("네트워크 인터페이스 조회 실패: %w", err)
	}

	attached := false
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// TC clsact qdisc 추가 (이미 있어도 무시)
		if err := attachTCFilter(iface.Name, program); err != nil {
			log.Printf("[경고] %s TC 필터 연결 실패: %v", iface.Name, err)
		} else {
			log.Printf("[+] %s TC 필터 연결 성공", iface.Name)
			attached = true
		}
	}

	if !attached {
		objs.Close()
		return fmt.Errorf("어떤 인터페이스에도 연결할 수 없습니다")
	}

	isAttached = true
	if err := os.WriteFile(stateFilePath, []byte("active"), 0644); err != nil {
		log.Printf("[경고] 상태 파일 생성 실패: %v", err)
	}

	return nil
}

// TC 필터 추가 함수 (tc 명령어 사용 - 가장 호환성 좋음)
func attachTCFilter(ifaceName string, prog *ebpf.Program) error {
	// 1. clsact qdisc 추가
	cmd := exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact")
	_ = cmd.Run() // 이미 있어도 에러 무시

	// 2. eBPF 프로그램을 임시 파일에 pin
	progPath := fmt.Sprintf("/sys/fs/bpf/ebpfw_prog_%s", ifaceName)
	os.Remove(progPath)
	if err := prog.Pin(progPath); err != nil {
		return fmt.Errorf("program pin 실패: %w", err)
	}

	// 3. Ingress 필터 추가
	cmdIngress := exec.Command("tc", "filter", "add", "dev", ifaceName,
		"ingress", "bpf", "da", "pinned", progPath,
		"sec", "tc")
	if err := cmdIngress.Run(); err != nil {
		return fmt.Errorf("ingress 필터 추가 실패: %w", err)
	}

	// 4. Egress 필터 추가
	cmdEgress := exec.Command("tc", "filter", "add", "dev", ifaceName,
		"egress", "bpf", "da", "pinned", progPath,
		"sec", "tc")
	if err := cmdEgress.Run(); err != nil {
		return fmt.Errorf("egress 필터 추가 실패: %w", err)
	}

	return nil
}

// TC 필터 제거
func detachTCFilter(ifaceName string) error {
	// Ingress 필터 삭제
	cmdIngress := exec.Command("tc", "filter", "del", "dev", ifaceName, "ingress")
	_ = cmdIngress.Run()

	// Egress 필터 삭제
	cmdEgress := exec.Command("tc", "filter", "del", "dev", ifaceName, "egress")
	_ = cmdEgress.Run()

	// qdisc 삭제
	cmdQdisc := exec.Command("tc", "qdisc", "del", "dev", ifaceName, "clsact")
	_ = cmdQdisc.Run()

	// 프로그램 unpin
	progPath := fmt.Sprintf("/sys/fs/bpf/ebpfw_prog_%s", ifaceName)
	os.Remove(progPath)

	return nil
}

func Detach() error {
	if !IsActive() {
		return fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
	}

	_ = ensureObjsLoaded()
	fmt.Println("[!] Detaching eBPF programs from interfaces...")

	// 모든 인터페이스에서 TC 필터 제거
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			detachTCFilter(iface.Name)
		}
	}

	fmt.Println("[!] All interfaces detached.")

	// Map unpin
	pinPath := "/sys/fs/bpf/ebpfw_rules"
	if objs.RulesArray != nil {
		_ = objs.RulesArray.Unpin()
	}
	os.Remove(pinPath)

	policyPinPath := "/sys/fs/bpf/ebpfw_policy"
	if objs.DefaultPolicy != nil {
		_ = objs.DefaultPolicy.Unpin()
	}
	os.Remove(policyPinPath)

	os.Remove(stateFilePath)

	if objs.FirewallFilter != nil {
		objs.Close()
	}

	isAttached = false
	program = nil
	return nil
}

func IsActive() bool {
	if isAttached {
		return true
	}
	_, err := os.Stat(stateFilePath)
	return err == nil
}

func ensureObjsLoaded() error {
	if isAttached && objs.FirewallFilter != nil {
		return nil
	}

	if _, err := os.Stat(stateFilePath); err == nil {
		if objs.RulesArray == nil {
			pinPath := "/sys/fs/bpf/ebpfw_rules"
			pinnedMap, err := ebpf.LoadPinnedMap(pinPath, nil)
			if err != nil {
				return fmt.Errorf("Pinned Map 로드 실패: %w", err)
			}
			objs.RulesArray = pinnedMap
		}

		if objs.DefaultPolicy == nil {
			policyPinPath := "/sys/fs/bpf/ebpfw_policy"
			pinnedPolicy, err := ebpf.LoadPinnedMap(policyPinPath, nil)
			if err != nil {
				return fmt.Errorf("Pinned Policy Map 로드 실패: %w", err)
			}
			objs.DefaultPolicy = pinnedPolicy
		}

		return nil
	}

	return fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
}

// 나머지 함수들 (UpdateRule, DeleteRule 등) 동일
func UpdateRule(index uint32, r *rule.Rule) error {
	if err := ensureObjsLoaded(); err != nil {
		return err
	}

	cRule := ebpf_fwFirewallRule{
		SrcIp:     r.SrcIP,
		DstIp:     r.DstIP,
		Port:      r.Port,
		Protocol:  uint8(r.Protocol),
		Direction: uint8(r.Direction),
		Action:    uint8(r.Action),
		Valid:     1,
	}

	return objs.RulesArray.Put(index, cRule)
}

func DeleteRule(index uint32) error {
	if err := ensureObjsLoaded(); err != nil {
		return err
	}

	cRule := ebpf_fwFirewallRule{
		Valid: 0,
	}

	return objs.RulesArray.Put(index, cRule)
}

func SyncAllRules(rules []rule.Rule) error {
	if err := ensureObjsLoaded(); err != nil {
		return err
	}

	emptyRule := ebpf_fwFirewallRule{Valid: 0}
	for i := uint32(0); i < MaxRules; i++ {
		if err := objs.RulesArray.Put(i, emptyRule); err != nil {
			return fmt.Errorf("규칙 초기화 실패 (index %d): %w", i, err)
		}
	}

	for i, r := range rules {
		if err := UpdateRule(uint32(i), &r); err != nil {
			return fmt.Errorf("규칙 동기화 실패 (index %d): %w", i, err)
		}
	}

	return nil
}

func ClearAllRules() error {
	if err := ensureObjsLoaded(); err != nil {
		return err
	}

	emptyRule := ebpf_fwFirewallRule{Valid: 0}
	for i := uint32(0); i < MaxRules; i++ {
		if err := objs.RulesArray.Put(i, emptyRule); err != nil {
			return fmt.Errorf("규칙 삭제 실패 (index %d): %w", i, err)
		}
	}

	return nil
}

func SetDefaultPolicy(direction rule.Direction, action rule.Action) error {
	if err := ensureObjsLoaded(); err != nil {
		return err
	}

	dirKey := uint32(direction)
	actionValue := uint8(action)
	return objs.DefaultPolicy.Put(dirKey, actionValue)
}

func GetDefaultPolicy(direction rule.Direction) (rule.Action, error) {
	if err := ensureObjsLoaded(); err != nil {
		return 0, err
	}

	dirKey := uint32(direction)
	var action uint8
	if err := objs.DefaultPolicy.Lookup(dirKey, &action); err != nil {
		return 0, fmt.Errorf("기본 정책 조회 실패: %w", err)
	}

	return rule.Action(action), nil
}

func GetAllRules() ([]rule.Rule, error) {
	if err := ensureObjsLoaded(); err != nil {
		return nil, err
	}

	var result []rule.Rule
	for i := uint32(0); i < MaxRules; i++ {
		var cRule ebpf_fwFirewallRule
		if err := objs.RulesArray.Lookup(i, &cRule); err != nil {
			continue
		}

		if cRule.Valid == 0 {
			continue
		}

		result = append(result, rule.Rule{
			SrcIP:     cRule.SrcIp,
			DstIP:     cRule.DstIp,
			Port:      cRule.Port,
			Protocol:  rule.Protocol(cRule.Protocol),
			Direction: rule.Direction(cRule.Direction),
			Action:    rule.Action(cRule.Action),
			Valid:     cRule.Valid,
		})
	}

	return result, nil
}
