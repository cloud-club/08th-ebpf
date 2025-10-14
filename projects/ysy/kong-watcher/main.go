package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "$BPF_CFLAGS -I./headers" -target amd64 -no-strip uprobe bpf/kong_uprobe_sidecar.c

// eBPF 객체 정의 (bpf2go가 생성하는 구조체)
type uprobeObjects struct {
	UprobeRead   *ebpf.Program `ebpf:"uprobe_read"`
	UprobeWrite  *ebpf.Program `ebpf:"uprobe_write"`
	HttpEvents   *ebpf.Map     `ebpf:"http_events"`
	HttpRequests *ebpf.Map     `ebpf:"http_requests"`
}

// eBPF 객체 로드 함수 (bpf2go가 생성)
func loadUprobeObjects(obj *uprobeObjects, opts *ebpf.CollectionOptions) error {
	// 실제 구현시 bpf2go가 생성하는 코드 사용
	// 여기서는 임시로 nil 반환
	return nil
}

// eBPF 객체 정리
func (obj *uprobeObjects) Close() error {
	if obj.UprobeRead != nil {
		obj.UprobeRead.Close()
	}
	if obj.UprobeWrite != nil {
		obj.UprobeWrite.Close()
	}
	if obj.HttpEvents != nil {
		obj.HttpEvents.Close()
	}
	if obj.HttpRequests != nil {
		obj.HttpRequests.Close()
	}
	return nil
}

// HTTP 요청 정보 구조체
type HTTPRequest struct {
	PID        uint32    `json:"pid"`
	TID        uint32    `json:"tid"`
	Timestamp  uint64    `json:"timestamp"`
	Method     uint8     `json:"method"`
	StatusCode uint32    `json:"status_code"`
	Path       [64]byte  `json:"path"`
	Host       [32]byte  `json:"host"`
	RemoteAddr [16]byte  `json:"remote_addr"`
	UserAgent  [128]byte `json:"user_agent"`
}

// Kong Gateway 프로세스 정보
type KongProcess struct {
	PID        uint32
	BinaryPath string
	Args       []string
}

func main() {
	log.Println("🚀 Kong Gateway eBPF Monitor 시작 (Sidecar 모드)")

	// 1. 리소스 제한 해제
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("❌ 메모리 제한 해제 실패: %v", err)
	}

	// 2. Kong Gateway 프로세스 찾기
	kongProcesses := findKongProcesses()
	if len(kongProcesses) == 0 {
		log.Println("⚠️  Kong Gateway 프로세스를 찾을 수 없습니다. 5초 후 재시도...")
		time.Sleep(5 * time.Second)
		kongProcesses = findKongProcesses()
		if len(kongProcesses) == 0 {
			log.Fatal("❌ Kong Gateway 프로세스를 찾을 수 없습니다")
		}
	}

	log.Printf("✅ Kong Gateway 프로세스 발견: %d개", len(kongProcesses))
	for _, proc := range kongProcesses {
		log.Printf("  📍 PID: %d, Binary: %s", proc.PID, proc.BinaryPath)
	}

	// 3. eBPF 객체 로드
	objs := uprobeObjects{}
	if err := loadUprobeObjects(&objs, nil); err != nil {
		log.Fatalf("❌ eBPF 객체 로드 실패: %v", err)
	}
	defer objs.Close()
	log.Printf("✅ eBPF 객체 로드 성공")

	// 4. uprobe 연결
	links := attachUprobes(&objs, kongProcesses)
	defer func() {
		for _, link := range links {
			if link != nil {
				link.Close()
			}
		}
	}()

	// 5. 컨텍스트 및 시그널 처리
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("🛑 종료 신호 수신, 프로그램 종료 중...")
		cancel()
	}()

	// 6. 이벤트 처리 시작
	go processEvents(ctx, &objs)
	go printStatus(ctx)

	log.Println("✅ Kong Gateway eBPF Monitor 실행 중...")
	log.Println("Ctrl-C를 눌러 종료")

	// 7. 메인 루프
	<-ctx.Done()
	log.Println("👋 Kong Gateway eBPF Monitor 종료")
}

// Kong Gateway 프로세스 찾기
func findKongProcesses() []KongProcess {
	var processes []KongProcess

	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("⚠️  프로세스 디렉토리 읽기 실패: %v", err)
		return processes
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		proc := getProcessInfo(uint32(pid))
		if proc != nil && isKongProcess(proc) {
			processes = append(processes, *proc)
		}
	}

	return processes
}

// 프로세스 정보 수집
func getProcessInfo(pid uint32) *KongProcess {
	// 명령행 정보 읽기
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdline, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return nil
	}

	args := strings.Split(string(cmdline), "\x00")
	if len(args) == 0 {
		return nil
	}

	// 바이너리 경로 읽기
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	binaryPath, err := os.Readlink(exePath)
	if err != nil {
		return nil
	}

	return &KongProcess{
		PID:        pid,
		BinaryPath: binaryPath,
		Args:       args,
	}
}

// Kong Gateway 프로세스인지 확인
func isKongProcess(proc *KongProcess) bool {
	binaryName := filepath.Base(proc.BinaryPath)
	cmdline := strings.Join(proc.Args, " ")

	keywords := []string{"kong", "nginx", "openresty", "lua", "gateway"}
	searchText := strings.ToLower(binaryName + " " + cmdline)

	for _, keyword := range keywords {
		if strings.Contains(searchText, keyword) {
			return true
		}
	}

	return false
}

// uprobe 연결
func attachUprobes(objs *uprobeObjects, processes []KongProcess) []link.Link {
	var links []link.Link

	// Kong 프로세스에 uprobe 연결 시도
	for _, proc := range processes {
		log.Printf("🔗 Kong 프로세스 %d에 uprobe 연결 시도: %s", proc.PID, proc.BinaryPath)

		exe, err := link.OpenExecutable(proc.BinaryPath)
		if err != nil {
			log.Printf("⚠️  바이너리 열기 실패 (PID: %d): %v", proc.PID, err)
			continue
		}

		// read/write 함수에 uprobe 연결
		if objs.UprobeRead != nil {
			link, err := exe.Uprobe("read", objs.UprobeRead, nil)
			if err != nil {
				log.Printf("⚠️  read uprobe 연결 실패: %v", err)
			} else {
				links = append(links, link)
				log.Printf("✅ read uprobe 연결 성공 (PID: %d)", proc.PID)
			}
		}

		if objs.UprobeWrite != nil {
			link, err := exe.Uprobe("write", objs.UprobeWrite, nil)
			if err != nil {
				log.Printf("⚠️  write uprobe 연결 실패: %v", err)
			} else {
				links = append(links, link)
				log.Printf("✅ write uprobe 연결 성공 (PID: %d)", proc.PID)
			}
		}
	}

	// Kong 프로세스에 연결 실패시 libc에 연결
	if len(links) == 0 {
		log.Println("⚠️  Kong 프로세스 uprobe 연결 실패. libc 연결 시도...")
		links = attachLibcUprobes(objs)
	}

	return links
}

// libc에 uprobe 연결 (대안)
func attachLibcUprobes(objs *uprobeObjects) []link.Link {
	var links []link.Link

	libcPaths := []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib64/libc.so.6",
	}

	for _, libcPath := range libcPaths {
		if _, err := os.Stat(libcPath); os.IsNotExist(err) {
			continue
		}

		log.Printf("🔗 libc uprobe 연결 시도: %s", libcPath)
		exe, err := link.OpenExecutable(libcPath)
		if err != nil {
			log.Printf("⚠️  libc 열기 실패: %v", err)
			continue
		}

		// read 함수 연결
		if objs.UprobeRead != nil {
			link, err := exe.Uprobe("read", objs.UprobeRead, nil)
			if err != nil {
				log.Printf("⚠️  libc read uprobe 연결 실패: %v", err)
			} else {
				links = append(links, link)
				log.Printf("✅ libc read uprobe 연결 성공: %s", libcPath)
			}
		}

		// write 함수 연결
		if objs.UprobeWrite != nil {
			link, err := exe.Uprobe("write", objs.UprobeWrite, nil)
			if err != nil {
				log.Printf("⚠️  libc write uprobe 연결 실패: %v", err)
			} else {
				links = append(links, link)
				log.Printf("✅ libc write uprobe 연결 성공: %s", libcPath)
			}
		}

		break // 첫 번째 성공한 libc 사용
	}

	return links
}

// 이벤트 처리
func processEvents(ctx context.Context, objs *uprobeObjects) {
	if objs.HttpEvents == nil {
		log.Println("⚠️  HttpEvents 맵이 없습니다.")
		return
	}

	reader, err := ringbuf.NewReader(objs.HttpEvents)
	if err != nil {
		log.Printf("⚠️  HttpEvents 리더 생성 실패: %v", err)
		return
	}
	defer reader.Close()

	log.Println("✅ Kong HTTP 이벤트 처리 시작")

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

			if len(record.RawSample) < int(unsafe.Sizeof(HTTPRequest{})) {
				continue
			}

			event := (*HTTPRequest)(unsafe.Pointer(&record.RawSample[0]))
			processEvent(event)
		}
	}
}

// 개별 이벤트 처리
func processEvent(event *HTTPRequest) {
	method := getHTTPMethod(event.Method)
	path := strings.TrimRight(string(event.Path[:]), "\x00")
	host := strings.TrimRight(string(event.Host[:]), "\x00")

	timestamp := time.Unix(0, int64(event.Timestamp))

	log.Printf("🌐 [%s] Kong HTTP: PID=%d, Method=%s, Path=%s, Host=%s, Status=%d",
		timestamp.Format("15:04:05"),
		event.PID,
		method,
		path,
		host,
		event.StatusCode)
}

// 상태 출력
func printStatus(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Println("📊 === Kong Gateway 모니터링 활성 상태 ===")
			log.Printf("✅ eBPF 프로그램 실행 중 (PID: %d)", os.Getpid())
			log.Println("=====================================")
		}
	}
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
