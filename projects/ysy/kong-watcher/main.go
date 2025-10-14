package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "$BPF_CFLAGS -I./headers" -target amd64 -no-strip bpf bpf/kong_monitor.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "$BPF_CFLAGS -I./headers" -target amd64 -no-strip kprobe bpf/kong_kprobe.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "$BPF_CFLAGS -I./headers" -target amd64 -no-strip uprobe bpf/kong_uprobe.c

// HTTP 요청 정보 구조체 (kprobe/uprobe용, 스택 크기 제한으로 축소)
type HTTPRequest struct {
	PID        uint32   `json:"pid"`
	TID        uint32   `json:"tid"`
	Timestamp  uint64   `json:"timestamp"`
	Method     uint8    `json:"method"`
	StatusCode uint32   `json:"status_code"`
	Path       [64]byte `json:"path"`
	Host       [32]byte `json:"host"`
}

// 연결 키 구조체 (eBPF C 구조체와 정확히 일치하도록 패딩 조정)
type ConnKey struct {
	SrcIP    uint32    `json:"src_ip"`
	DstIP    uint32    `json:"dst_ip"`
	SrcPort  uint16    `json:"src_port"`
	DstPort  uint16    `json:"dst_port"`
	Protocol uint8     `json:"protocol"`
	Method   uint8     `json:"method"`
	_        [2]byte   // 패딩 (C 구조체와 정확히 맞추기 위해)
	Domain   [64]byte  `json:"domain"`
	Path     [128]byte `json:"path"`
}

// 연결 통계 구조체
type ConnStats struct {
	RequestCount  uint64 `json:"request_count"`
	ResponseCount uint64 `json:"response_count"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	ErrorCount    uint64 `json:"error_count"`
	LastSeen      uint64 `json:"last_seen"`
}

// 컨테이너 통계 구조체
type ContainerStats struct {
	TotalRequests      uint64 `json:"total_requests"`
	TotalResponses     uint64 `json:"total_responses"`
	TotalBytesSent     uint64 `json:"total_bytes_sent"`
	TotalBytesReceived uint64 `json:"total_bytes_received"`
	TotalErrors        uint64 `json:"total_errors"`
	LastActivity       uint64 `json:"last_activity"`
}

// 트래픽 이벤트 구조체
type TrafficEvent struct {
	EventType  uint32    `json:"event_type"`
	SrcIP      uint32    `json:"src_ip"`
	DstIP      uint32    `json:"dst_ip"`
	SrcPort    uint16    `json:"src_port"`
	DstPort    uint16    `json:"dst_port"`
	Method     uint8     `json:"method"`
	Domain     [64]byte  `json:"domain"`
	Path       [128]byte `json:"path"`
	Timestamp  uint64    `json:"timestamp"`
	Bytes      uint64    `json:"bytes"`
	StatusCode uint32    `json:"status_code"`
}

func main() {
	log.Println("Kong Gateway eBPF Monitor 시작")

	// 1. 리소스 제한 해제
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("메모리 제한 해제 실패: %v", err)
	}

	// 2. eBPF 객체 로드
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Printf("⚠️  XDP eBPF 객체 로드 실패: %v", err)
		log.Printf("⚠️  kprobe/uprobe 방식으로 전환합니다")
	} else {
		defer objs.Close()
		log.Printf("✅ XDP eBPF 객체 로드 성공")
	}

	// Kong Gateway 프로세스 식별
	kongPIDs := findKongProcesses()
	if len(kongPIDs) == 0 {
		log.Printf("⚠️  Kong Gateway 프로세스를 찾을 수 없습니다")
	} else {
		log.Printf("✅ Kong Gateway 프로세스 발견: %v", kongPIDs)
	}

	// kprobe eBPF 객체 로드
	kprobeObjs := kprobeObjects{}
	if err := loadKprobeObjects(&kprobeObjs, nil); err != nil {
		log.Printf("⚠️  kprobe eBPF 객체 로드 실패: %v", err)
	} else {
		defer kprobeObjs.Close()
		log.Printf("✅ kprobe eBPF 객체 로드 성공")

		// Kong Gateway 프로세스 정보를 eBPF 맵에 등록
		registerKongProcesses(&kprobeObjs, kongPIDs)
	}

	// uprobe eBPF 객체 로드
	uprobeObjs := uprobeObjects{}
	if err := loadUprobeObjects(&uprobeObjs, nil); err != nil {
		log.Printf("⚠️  uprobe eBPF 객체 로드 실패: %v", err)
	} else {
		defer uprobeObjs.Close()
		log.Printf("✅ uprobe eBPF 객체 로드 성공")

		// Kong Gateway 프로세스 정보를 eBPF 맵에 등록
		registerKongProcesses(&uprobeObjs, kongPIDs)
	}

	// 3. 네트워크 인터페이스 찾기 (자동 감지 또는 지정)
	var ifaceName string
	var err error
	var interfaces []net.Interface

	if len(os.Args) > 1 {
		// 명령행에서 인터페이스 지정
		ifaceName = os.Args[1]
		_, err = net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("네트워크 인터페이스 %q 찾기 실패: %v", ifaceName, err)
		}
	} else {
		// 자동으로 활성 인터페이스 찾기
		interfaces, err = net.Interfaces()
		if err != nil {
			log.Fatalf("네트워크 인터페이스 목록 조회 실패: %v", err)
		}

		// 우선순위: eth0, ens*, eno*, enp*, wlan*
		preferredNames := []string{"eth0", "ens", "eno", "enp", "wlan"}

		for _, preferred := range preferredNames {
			for _, iface := range interfaces {
				if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagLoopback) == 0 {
					if preferred == "eth0" && iface.Name == "eth0" {
						ifaceName = iface.Name
						break
					} else if preferred != "eth0" && len(iface.Name) >= len(preferred) && iface.Name[:len(preferred)] == preferred {
						ifaceName = iface.Name
						break
					}
				}
			}
			if ifaceName != "" {
				break
			}
		}

		if ifaceName == "" {
			// 기본값으로 첫 번째 활성 인터페이스 사용
			for _, iface := range interfaces {
				if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagLoopback) == 0 {
					ifaceName = iface.Name
					break
				}
			}
		}

		if ifaceName == "" {
			log.Fatal("사용 가능한 네트워크 인터페이스를 찾을 수 없습니다")
		}

		_, err = net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("네트워크 인터페이스 %q 찾기 실패: %v", ifaceName, err)
		}
	}

	// 4. XDP 프로그램 연결 (우선)
	var xdpLink link.Link
	if objs.XdpKongMonitor != nil {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Printf("⚠️  인터페이스 %s 찾기 실패: %v", ifaceName, err)
		} else {
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   objs.XdpKongMonitor,
				Interface: iface.Index,
				Flags:     link.XDPGenericMode,
			})
			if err != nil {
				log.Printf("⚠️  XDP 프로그램 연결 실패: %v", err)
			} else {
				defer xdpLink.Close()
				log.Printf("✅ XDP 프로그램 연결 성공 (인터페이스: %s)", ifaceName)
			}
		}
	}

	// 5. kprobe/uprobe 프로그램 연결
	var kprobeLinks []link.Link
	var uprobeLinks []link.Link

	// kprobe 연결
	if kprobeObjs.KprobeSysRead != nil {
		kprobeLink, err := link.Kprobe("__x64_sys_read", kprobeObjs.KprobeSysRead, nil)
		if err != nil {
			log.Printf("⚠️  kprobe sys_read 연결 실패: %v", err)
		} else {
			kprobeLinks = append(kprobeLinks, kprobeLink)
			log.Printf("✅ kprobe sys_read 연결 성공")
		}
	}

	if kprobeObjs.KprobeSysWrite != nil {
		kprobeLink, err := link.Kprobe("__x64_sys_write", kprobeObjs.KprobeSysWrite, nil)
		if err != nil {
			log.Printf("⚠️  kprobe sys_write 연결 실패: %v", err)
		} else {
			kprobeLinks = append(kprobeLinks, kprobeLink)
			log.Printf("✅ kprobe sys_write 연결 성공")
		}
	}

	// uprobe 연결 (libc 함수들)
	if uprobeObjs.UprobeRead != nil {
		uprobeLink, err := link.OpenExecutable("/lib/x86_64-linux-gnu/libc.so.6")
		if err != nil {
			log.Printf("⚠️  libc.so.6 열기 실패: %v", err)
		} else {
			link, err := uprobeLink.Uprobe("read", uprobeObjs.UprobeRead, nil)
			if err != nil {
				log.Printf("⚠️  uprobe read 연결 실패: %v", err)
			} else {
				uprobeLinks = append(uprobeLinks, link)
				log.Printf("✅ uprobe read 연결 성공")
			}
		}
	}

	if uprobeObjs.UprobeWrite != nil {
		uprobeLink, err := link.OpenExecutable("/lib/x86_64-linux-gnu/libc.so.6")
		if err != nil {
			log.Printf("⚠️  libc.so.6 열기 실패: %v", err)
		} else {
			link, err := uprobeLink.Uprobe("write", uprobeObjs.UprobeWrite, nil)
			if err != nil {
				log.Printf("⚠️  uprobe write 연결 실패: %v", err)
			} else {
				uprobeLinks = append(uprobeLinks, link)
				log.Printf("✅ uprobe write 연결 성공")
			}
		}
	}

	// 연결 정리
	defer func() {
		for _, l := range kprobeLinks {
			l.Close()
		}
		for _, l := range uprobeLinks {
			l.Close()
		}
	}()

	log.Printf("✅ kprobe/uprobe 프로그램 연결 완료")
	log.Printf("  - HTTP 시스템 콜 추적 (read, write, send, recv)")
	log.Printf("  - HTTP 헤더 파싱 (Host, Path, User-Agent, Content-Length)")
	log.Printf("  - HTTP 상태 코드 추적")
	log.Println("Ctrl-C를 눌러 종료")

	// 6. 컨텍스트 생성 및 시그널 처리
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 시그널 처리
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("종료 신호 수신, 프로그램 종료 중...")
		cancel()
	}()

	// 7. 통계 수집 및 출력
	go collectStats(ctx, &objs)
	go collectHTTPStats(ctx, &kprobeObjs, &uprobeObjs)

	// 8. 실시간 이벤트 처리
	go processEvents(ctx, &objs)
	go processHTTPEvents(ctx, &kprobeObjs, &uprobeObjs)

	// 9. 메인 루프
	<-ctx.Done()
	log.Println("Kong Gateway eBPF Monitor 종료")
}

// 통계 수집 및 출력
func collectStats(ctx context.Context, objs *bpfObjects) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printStats(objs)
		}
	}
}

// 통계 출력
func printStats(objs *bpfObjects) {
	log.Println("=== Kong Gateway 트래픽 통계 ===")

	// eBPF 객체가 로드되지 않은 경우
	if objs == nil || objs.ContainerStatsMap == nil {
		log.Println("⚠️  eBPF 객체가 로드되지 않았습니다.")
		return
	}

	// 컨테이너별 통계 출력
	var containerID uint32 = 0
	var containerStats ContainerStats
	if err := objs.ContainerStatsMap.Lookup(containerID, &containerStats); err == nil {
		log.Printf("컨테이너 통계:")
		log.Printf("  총 요청 수: %d", containerStats.TotalRequests)
		log.Printf("  총 응답 수: %d", containerStats.TotalResponses)
		log.Printf("  총 송신 바이트: %d", containerStats.TotalBytesSent)
		log.Printf("  총 수신 바이트: %d", containerStats.TotalBytesReceived)
		log.Printf("  총 에러 수: %d", containerStats.TotalErrors)
		if containerStats.LastActivity > 0 {
			// bpf_ktime_get_ns()는 나노초 단위이므로 Unix 시간으로 변환
			unixTime := int64(containerStats.LastActivity / 1000000000) // 나노초를 초로 변환
			log.Printf("  마지막 활동: %s", time.Unix(unixTime, 0).Format(time.RFC3339))
		} else {
			log.Printf("  마지막 활동: 없음")
		}
	}

	// 연결별 통계 샘플 출력 (최대 5개)
	if objs.ConnMap == nil {
		log.Println("⚠️  ConnMap이 로드되지 않았습니다.")
		return
	}

	iter := objs.ConnMap.Iterate()
	var key ConnKey
	var stats ConnStats
	count := 0
	for iter.Next(&key, &stats) && count < 5 {
		srcIP := net.IP{byte(key.SrcIP), byte(key.SrcIP >> 8), byte(key.SrcIP >> 16), byte(key.SrcIP >> 24)}
		dstIP := net.IP{byte(key.DstIP), byte(key.DstIP >> 8), byte(key.DstIP >> 16), byte(key.DstIP >> 24)}

		method := getHTTPMethod(key.Method)
		domain := string(key.Domain[:])
		path := string(key.Path[:])

		log.Printf("연결 %d:", count+1)
		log.Printf("  %s:%d -> %s:%d", srcIP.String(), key.SrcPort, dstIP.String(), key.DstPort)
		log.Printf("  메서드: %s, 도메인: %s, 경로: %s", method, domain, path)
		log.Printf("  요청 수: %d, 응답 수: %d", stats.RequestCount, stats.ResponseCount)
		log.Printf("  송신: %d bytes, 수신: %d bytes", stats.BytesSent, stats.BytesReceived)
		log.Printf("  에러 수: %d", stats.ErrorCount)
		if stats.LastSeen > 0 {
			// bpf_ktime_get_ns()는 나노초 단위이므로 Unix 시간으로 변환
			unixTime := int64(stats.LastSeen / 1000000000) // 나노초를 초로 변환
			log.Printf("  마지막 활동: %s", time.Unix(unixTime, 0).Format(time.RFC3339))
		} else {
			log.Printf("  마지막 활동: 없음")
		}
		count++
	}
	if err := iter.Err(); err != nil {
		log.Printf("연결 맵 순회 중 오류: %v", err)
	}

	log.Println("================================")
}

// 실시간 이벤트 처리
func processEvents(ctx context.Context, objs *bpfObjects) {
	if objs.TrafficEvents == nil {
		log.Println("⚠️  TrafficEvents 맵이 없습니다.")
		return
	}

	reader, err := ringbuf.NewReader(objs.TrafficEvents)
	if err != nil {
		log.Printf("⚠️  TrafficEvents 리더 생성 실패: %v", err)
		return
	}
	defer reader.Close()

	log.Println("✅ 실시간 트래픽 이벤트 처리 시작")

	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if err.Error() == "closed" {
					return
				}
				continue
			}

			// ring buffer에서 직접 구조체로 읽기
			if len(record.RawSample) < int(unsafe.Sizeof(TrafficEvent{})) {
				continue
			}

			event := (*TrafficEvent)(unsafe.Pointer(&record.RawSample[0]))
			processEvent(event)
		}
	}
}

// 개별 이벤트 처리
func processEvent(event *TrafficEvent) {
	srcIP := net.IP{byte(event.SrcIP), byte(event.SrcIP >> 8), byte(event.SrcIP >> 16), byte(event.SrcIP >> 24)}
	dstIP := net.IP{byte(event.DstIP), byte(event.DstIP >> 8), byte(event.DstIP >> 16), byte(event.DstIP >> 24)}

	method := getHTTPMethod(event.Method)
	domain := string(event.Domain[:])
	path := string(event.Path[:])

	eventType := getEventType(event.EventType)
	timestamp := time.Unix(0, int64(event.Timestamp))

	log.Printf("[%s] %s %s:%d -> %s:%d | %s %s%s | %d bytes | 상태: %d",
		timestamp.Format("15:04:05"),
		eventType,
		srcIP.String(), event.SrcPort,
		dstIP.String(), event.DstPort,
		method, domain, path,
		event.Bytes,
		event.StatusCode)
}

// HTTP 메서드 문자열 변환
func getHTTPMethod(method uint8) string {
	switch method {
	case 1:
		return "GET"
	case 2:
		return "POST"
	case 3:
		return "PUT"
	case 4:
		return "DELETE"
	case 5:
		return "PATCH"
	case 6:
		return "HEAD"
	case 7:
		return "OPTIONS"
	default:
		return "UNKNOWN"
	}
}

// 이벤트 타입 문자열 변환
func getEventType(eventType uint32) string {
	switch eventType {
	case 1:
		return "REQUEST"
	case 2:
		return "RESPONSE"
	case 3:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// HTTP 이벤트 처리 (kprobe/uprobe)
func processHTTPEvents(ctx context.Context, kprobeObjs *kprobeObjects, uprobeObjs *uprobeObjects) {
	// kprobe 이벤트 처리
	if kprobeObjs.HttpEvents != nil {
		reader, err := ringbuf.NewReader(kprobeObjs.HttpEvents)
		if err != nil {
			log.Printf("kprobe HTTP 이벤트 리더 생성 실패: %v", err)
			return
		}
		defer reader.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := reader.Read()
				if err != nil {
					if err.Error() == "closed" {
						return
					}
					continue
				}

				var event HTTPRequest
				if err := json.Unmarshal(record.RawSample, &event); err != nil {
					log.Printf("kprobe HTTP 이벤트 파싱 실패: %v", err)
					continue
				}

				log.Printf("🔍 kprobe HTTP 이벤트: PID=%d, Method=%s, Path=%s, Host=%s, Status=%d",
					event.PID, getHTTPMethod(event.Method),
					string(event.Path[:]), string(event.Host[:]), event.StatusCode)
			}
		}
	}

	// uprobe 이벤트 처리
	if uprobeObjs.HttpEvents != nil {
		reader, err := ringbuf.NewReader(uprobeObjs.HttpEvents)
		if err != nil {
			log.Printf("uprobe HTTP 이벤트 리더 생성 실패: %v", err)
			return
		}
		defer reader.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := reader.Read()
				if err != nil {
					if err.Error() == "closed" {
						return
					}
					continue
				}

				var event HTTPRequest
				if err := json.Unmarshal(record.RawSample, &event); err != nil {
					log.Printf("uprobe HTTP 이벤트 파싱 실패: %v", err)
					continue
				}

				log.Printf("🔍 uprobe HTTP 이벤트: PID=%d, Method=%s, Path=%s, Host=%s, Status=%d",
					event.PID, getHTTPMethod(event.Method),
					string(event.Path[:]), string(event.Host[:]), event.StatusCode)
			}
		}
	}
}

// HTTP 통계 수집
func collectHTTPStats(ctx context.Context, kprobeObjs *kprobeObjects, uprobeObjs *uprobeObjects) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printHTTPStats(kprobeObjs, uprobeObjs)
		}
	}
}

// HTTP 통계 출력
func printHTTPStats(kprobeObjs *kprobeObjects, uprobeObjs *uprobeObjects) {
	log.Println("=== HTTP 트래픽 통계 (kprobe/uprobe) ===")

	// eBPF 객체가 로드되지 않은 경우
	if kprobeObjs == nil && uprobeObjs == nil {
		log.Println("⚠️  kprobe/uprobe eBPF 객체가 로드되지 않았습니다.")
		return
	}

	// kprobe 통계
	if kprobeObjs != nil && kprobeObjs.HttpRequests != nil {
		iter := kprobeObjs.HttpRequests.Iterate()
		var pid uint32
		var req HTTPRequest
		count := 0
		for iter.Next(&pid, &req) && count < 5 {
			log.Printf("kprobe HTTP 요청 %d:", count+1)
			log.Printf("  PID: %d, Method: %s", req.PID, getHTTPMethod(req.Method))
			log.Printf("  Path: %s, Host: %s", string(req.Path[:]), string(req.Host[:]))
			log.Printf("  Status: %d", req.StatusCode)
			if req.Timestamp > 0 {
				unixTime := int64(req.Timestamp / 1000000000)
				log.Printf("  Timestamp: %s", time.Unix(unixTime, 0).Format(time.RFC3339))
			}
			count++
		}
		if err := iter.Err(); err != nil {
			log.Printf("kprobe HTTP 맵 순회 중 오류: %v", err)
		}
	}

	// uprobe 통계
	if uprobeObjs != nil && uprobeObjs.HttpRequests != nil {
		iter := uprobeObjs.HttpRequests.Iterate()
		var pid uint32
		var req HTTPRequest
		count := 0
		for iter.Next(&pid, &req) && count < 5 {
			log.Printf("uprobe HTTP 요청 %d:", count+1)
			log.Printf("  PID: %d, Method: %s", req.PID, getHTTPMethod(req.Method))
			log.Printf("  Path: %s, Host: %s", string(req.Path[:]), string(req.Host[:]))
			log.Printf("  Status: %d", req.StatusCode)
			if req.Timestamp > 0 {
				unixTime := int64(req.Timestamp / 1000000000)
				log.Printf("  Timestamp: %s", time.Unix(unixTime, 0).Format(time.RFC3339))
			}
			count++
		}
		if err := iter.Err(); err != nil {
			log.Printf("uprobe HTTP 맵 순회 중 오류: %v", err)
		}
	}

	log.Println("==========================================")
}

// Kong Gateway 프로세스 찾기 (Kubernetes 환경 최적화)
func findKongProcesses() []uint32 {
	var pids []uint32

	// 1. ps 명령어로 Kong 관련 프로세스 찾기
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("프로세스 목록 조회 실패: %v", err)
		return pids
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Kong Gateway 관련 프로세스 필터링
		if strings.Contains(line, "kong") ||
			strings.Contains(line, "nginx") ||
			strings.Contains(line, "openresty") ||
			strings.Contains(line, "lua") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if pid, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
					pids = append(pids, uint32(pid))
					log.Printf("🔍 Kong 관련 프로세스 발견: PID=%d, CMD=%s", pid, line)
				}
			}
		}
	}

	// 2. Kubernetes Pod에서 Kong Gateway 프로세스 찾기
	kongPods := findKongPods()
	for _, pod := range kongPods {
		log.Printf("🔍 Kong Pod 발견: %s", pod)
	}

	return pids
}

// Kubernetes에서 Kong Gateway Pod 찾기
func findKongPods() []string {
	var pods []string

	// kubectl 명령어로 Kong 관련 Pod 찾기
	cmd := exec.Command("kubectl", "get", "pods", "-o", "name", "--no-headers")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Kubernetes Pod 목록 조회 실패: %v", err)
		return pods
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "kong") {
			pods = append(pods, strings.TrimSpace(line))
		}
	}

	return pods
}

// Kong Gateway 프로세스를 eBPF 맵에 등록
func registerKongProcesses(objs interface{}, pids []uint32) {
	if len(pids) == 0 {
		log.Printf("⚠️  등록할 Kong 프로세스가 없습니다")
		return
	}

	// kprobe 객체인지 uprobe 객체인지 확인
	switch obj := objs.(type) {
	case *kprobeObjects:
		if obj.KongProcesses != nil {
			for _, pid := range pids {
				value := uint8(1) // Kong Gateway 프로세스로 표시
				if err := obj.KongProcesses.Put(pid, value); err != nil {
					log.Printf("❌ Kong 프로세스 %d 등록 실패: %v", pid, err)
				} else {
					log.Printf("✅ Kong 프로세스 %d 등록 성공 (kprobe)", pid)
				}
			}
		} else {
			log.Printf("⚠️  kprobe KongProcesses 맵이 없습니다")
		}
	case *uprobeObjects:
		if obj.KongProcesses != nil {
			for _, pid := range pids {
				value := uint8(1) // Kong Gateway 프로세스로 표시
				if err := obj.KongProcesses.Put(pid, value); err != nil {
					log.Printf("❌ Kong 프로세스 %d 등록 실패: %v", pid, err)
				} else {
					log.Printf("✅ Kong 프로세스 %d 등록 성공 (uprobe)", pid)
				}
			}
		} else {
			log.Printf("⚠️  uprobe KongProcesses 맵이 없습니다")
		}
	default:
		log.Printf("⚠️  알 수 없는 eBPF 객체 타입")
	}
}
