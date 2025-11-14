package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	UprobeRead             *ebpf.Program `ebpf:"uprobe_read"`
	UprobeWrite            *ebpf.Program `ebpf:"uprobe_write"`
	UprobeKongHttpRequest  *ebpf.Program `ebpf:"uprobe_kong_http_request"`
	UprobeKongHttpResponse *ebpf.Program `ebpf:"uprobe_kong_http_response"`
	UprobeKongLuaHandler   *ebpf.Program `ebpf:"uprobe_kong_lua_handler"`
	HttpEvents             *ebpf.Map     `ebpf:"http_events"`
	HttpRequests           *ebpf.Map     `ebpf:"http_requests"`
	KongProcesses          *ebpf.Map     `ebpf:"kong_processes"`
	RequestStartTimes      *ebpf.Map     `ebpf:"request_start_times"`
}

// HTTP 요청 정보 구조체 (개선된 버전)
type HTTPRequest struct {
	PID            uint32    `json:"pid"`
	TID            uint32    `json:"tid"`
	Timestamp      uint64    `json:"timestamp"`
	Method         uint8     `json:"method"`
	StatusCode     uint32    `json:"status_code"`
	ResponseTimeNs uint64    `json:"response_time_ns"`
	Path           [64]byte  `json:"path"`
	Host           [32]byte  `json:"host"`
	RemoteAddr     [16]byte  `json:"remote_addr"`
	UserAgent      [128]byte `json:"user_agent"`
	ErrorCode      uint8     `json:"error_code"`
}

// Kong Gateway 프로세스 정보
type KongProcess struct {
	PID        uint32    `json:"pid"`
	BinaryPath string    `json:"binary_path"`
	Args       []string  `json:"args"`
	StartTime  time.Time `json:"start_time"`
}

// 모니터링 통계
type MonitorStats struct {
	TotalRequests   int64 `json:"total_requests"`
	TotalResponses  int64 `json:"total_responses"`
	ErrorCount      int64 `json:"error_count"`
	AvgResponseTime int64 `json:"avg_response_time_ns"`
	LastRequestTime int64 `json:"last_request_time"`
}

// 설정 구조체
type Config struct {
	LogLevel      string        `json:"log_level"`
	StatsInterval time.Duration `json:"stats_interval"`
	MaxRetries    int           `json:"max_retries"`
	RetryDelay    time.Duration `json:"retry_delay"`
	EnableJSONLog bool          `json:"enable_json_log"`
	EnableMetrics bool          `json:"enable_metrics"`
}

// 전역 변수
var (
	logger     *slog.Logger
	config     *Config
	stats      MonitorStats
	statsMutex sync.RWMutex
)

func main() {
	// 초기화
	if err := initialize(); err != nil {
		log.Fatalf("❌ 초기화 실패: %v", err)
	}
	defer cleanup()

	logger.Info("🚀 Kong Gateway eBPF Monitor 시작 (Kubernetes Sidecar 모드)")

	// 1. 리소스 제한 해제
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Error("메모리 제한 해제 실패", "error", err)
		return
	}
	logger.Debug("메모리 제한 해제 성공")

	// 2. Kong Gateway 프로세스 찾기 (재시도 로직 포함)
	var kongProcesses []KongProcess
	for i := 0; i < config.MaxRetries; i++ {
		kongProcesses = findKongProcesses()
		if len(kongProcesses) > 0 {
			break
		}

		if i < config.MaxRetries-1 {
			logger.Warn("Kong Gateway 프로세스를 찾을 수 없습니다. 재시도 중...",
				"attempt", i+1,
				"max_retries", config.MaxRetries,
				"retry_delay", config.RetryDelay)
			time.Sleep(config.RetryDelay)
		}
	}

	if len(kongProcesses) == 0 {
		logger.Error("Kong Gateway 프로세스를 찾을 수 없습니다",
			"max_retries", config.MaxRetries)
		return
	}

	logger.Info("Kong Gateway 프로세스 발견", "count", len(kongProcesses))
	for _, proc := range kongProcesses {
		logger.Info("Kong 프로세스", "pid", proc.PID, "binary", proc.BinaryPath)
	}

	// 3. eBPF 객체 로드
	objs := uprobeObjects{}
	if err := loadUprobeObjects(&objs, nil); err != nil {
		logger.Error("eBPF 객체 로드 실패", "error", err)
		return
	}
	defer objs.Close()
	logger.Info("eBPF 객체 로드 성공")

	// 4. uprobe 연결
	links := attachUprobes(&objs, kongProcesses)
	defer func() {
		for _, link := range links {
			if link != nil {
				link.Close()
			}
		}
	}()

	if len(links) == 0 {
		logger.Error("uprobe 연결 실패")
		return
	}

	// 5. 컨텍스트 및 시그널 처리
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("종료 신호 수신, 프로그램 종료 중...")
		cancel()
	}()

	// 6. 이벤트 처리 시작
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		processEvents(ctx, &objs)
	}()

	go func() {
		defer wg.Done()
		printStatus(ctx)
	}()

	logger.Info("Kong Gateway eBPF Monitor 실행 중...")
	logger.Info("Ctrl-C를 눌러 종료")

	// 7. 메인 루프
	<-ctx.Done()
	wg.Wait()
	logger.Info("Kong Gateway eBPF Monitor 종료")
}

// Kong Gateway 프로세스 찾기 (Kubernetes 사이드카 환경 최적화)
func findKongProcesses() []KongProcess {
	var processes []KongProcess

	// Kubernetes 사이드카 환경에서는 호스트 프로세스 네임스페이스 사용
	procPath := detectProcPath()
	logger.Debug("프로세스 디렉토리 사용", "path", procPath)

	entries, err := os.ReadDir(procPath)
	if err != nil {
		logger.Error("프로세스 디렉토리 읽기 실패", "path", procPath, "error", err)
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

		proc := getProcessInfo(uint32(pid), procPath)
		if proc != nil && isKongProcess(proc) {
			processes = append(processes, *proc)
		}
	}

	return processes
}

// 프로세스 디렉토리 경로 감지 (Kubernetes 환경 고려)
func detectProcPath() string {
	// Kubernetes 사이드카에서는 호스트 프로세스 네임스페이스 공유
	possiblePaths := []string{
		"/host/proc", // Kubernetes 사이드카에서 호스트 프로세스 접근
		"/proc",      // 일반적인 Linux 환경
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			// 디렉토리가 존재하고 읽기 가능한지 확인
			if entries, err := os.ReadDir(path); err == nil && len(entries) > 0 {
				return path
			}
		}
	}

	// 기본값으로 /proc 사용
	return "/proc"
}

// 프로세스 정보 수집 (Kubernetes 환경 고려)
func getProcessInfo(pid uint32, procPath string) *KongProcess {
	// 명령행 정보 읽기
	cmdlinePath := fmt.Sprintf("%s/%d/cmdline", procPath, pid)
	cmdline, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return nil
	}

	args := strings.Split(string(cmdline), "\x00")
	if len(args) == 0 {
		return nil
	}

	// 바이너리 경로 읽기
	exePath := fmt.Sprintf("%s/%d/exe", procPath, pid)
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

// Kong Gateway 프로세스인지 확인 (사이드카 환경 최적화)
func isKongProcess(proc *KongProcess) bool {
	binaryName := filepath.Base(proc.BinaryPath)
	cmdline := strings.Join(proc.Args, " ")

	// Kong Gateway 관련 키워드들
	keywords := []string{"kong", "nginx", "openresty", "lua", "gateway"}
	searchText := strings.ToLower(binaryName + " " + cmdline)

	for _, keyword := range keywords {
		if strings.Contains(searchText, keyword) {
			logger.Debug("Kong 프로세스 감지", "pid", proc.PID, "binary", binaryName, "keyword", keyword)
			return true
		}
	}

	// 환경 변수로 Kong 프로세스 이름 지정 가능
	if kongProcessName := os.Getenv("KONG_PROCESS_NAME"); kongProcessName != "" {
		if strings.Contains(strings.ToLower(binaryName), strings.ToLower(kongProcessName)) {
			logger.Debug("환경 변수로 지정된 Kong 프로세스 감지", "pid", proc.PID, "binary", binaryName)
			return true
		}
	}

	return false
}

// uprobe 연결 (개선된 버전)
func attachUprobes(objs *uprobeObjects, processes []KongProcess) []link.Link {
	var links []link.Link

	// Kong 프로세스에 uprobe 연결 시도
	for _, proc := range processes {
		logger.Info("Kong 프로세스에 uprobe 연결 시도", "pid", proc.PID, "binary", proc.BinaryPath)

		exe, err := link.OpenExecutable(proc.BinaryPath)
		if err != nil {
			logger.Warn("바이너리 열기 실패", "pid", proc.PID, "error", err)
			continue
		}

		// Kong 프로세스를 맵에 등록
		if objs.KongProcesses != nil {
			kongFlag := uint8(1)
			if err := objs.KongProcesses.Put(proc.PID, kongFlag); err != nil {
				logger.Warn("Kong 프로세스 등록 실패", "pid", proc.PID, "error", err)
			}
		}

		// read/write 함수에 uprobe 연결
		if objs.UprobeRead != nil {
			link, err := exe.Uprobe("read", objs.UprobeRead, nil)
			if err != nil {
				logger.Warn("read uprobe 연결 실패", "pid", proc.PID, "error", err)
			} else {
				links = append(links, link)
				logger.Info("read uprobe 연결 성공", "pid", proc.PID)
			}
		}

		if objs.UprobeWrite != nil {
			link, err := exe.Uprobe("write", objs.UprobeWrite, nil)
			if err != nil {
				logger.Warn("write uprobe 연결 실패", "pid", proc.PID, "error", err)
			} else {
				links = append(links, link)
				logger.Info("write uprobe 연결 성공", "pid", proc.PID)
			}
		}

		// Kong 특화 uprobe 연결 시도
		if objs.UprobeKongHttpRequest != nil {
			link, err := exe.Uprobe("ngx_http_process_request", objs.UprobeKongHttpRequest, nil)
			if err != nil {
				logger.Debug("Kong HTTP request uprobe 연결 실패", "pid", proc.PID, "error", err)
			} else {
				links = append(links, link)
				logger.Info("Kong HTTP request uprobe 연결 성공", "pid", proc.PID)
			}
		}

		if objs.UprobeKongHttpResponse != nil {
			link, err := exe.Uprobe("ngx_http_send_response", objs.UprobeKongHttpResponse, nil)
			if err != nil {
				logger.Debug("Kong HTTP response uprobe 연결 실패", "pid", proc.PID, "error", err)
			} else {
				links = append(links, link)
				logger.Info("Kong HTTP response uprobe 연결 성공", "pid", proc.PID)
			}
		}
	}

	// Kong 프로세스에 연결 실패시 libc에 연결
	if len(links) == 0 {
		logger.Warn("Kong 프로세스 uprobe 연결 실패. libc 연결 시도...")
		links = attachLibcUprobes(objs)
	}

	return links
}

// libc에 uprobe 연결 (개선된 버전)
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

		logger.Info("libc uprobe 연결 시도", "path", libcPath)
		exe, err := link.OpenExecutable(libcPath)
		if err != nil {
			logger.Warn("libc 열기 실패", "path", libcPath, "error", err)
			continue
		}

		// read 함수 연결
		if objs.UprobeRead != nil {
			link, err := exe.Uprobe("read", objs.UprobeRead, nil)
			if err != nil {
				logger.Warn("libc read uprobe 연결 실패", "path", libcPath, "error", err)
			} else {
				links = append(links, link)
				logger.Info("libc read uprobe 연결 성공", "path", libcPath)
			}
		}

		// write 함수 연결
		if objs.UprobeWrite != nil {
			link, err := exe.Uprobe("write", objs.UprobeWrite, nil)
			if err != nil {
				logger.Warn("libc write uprobe 연결 실패", "path", libcPath, "error", err)
			} else {
				links = append(links, link)
				logger.Info("libc write uprobe 연결 성공", "path", libcPath)
			}
		}

		break // 첫 번째 성공한 libc 사용
	}

	return links
}

// 이벤트 처리 (개선된 버전)
func processEvents(ctx context.Context, objs *uprobeObjects) {
	if objs.HttpEvents == nil {
		logger.Error("HttpEvents 맵이 없습니다")
		return
	}

	reader, err := ringbuf.NewReader(objs.HttpEvents)
	if err != nil {
		logger.Error("HttpEvents 리더 생성 실패", "error", err)
		return
	}
	defer reader.Close()

	logger.Info("Kong HTTP 이벤트 처리 시작")

	for {
		select {
		case <-ctx.Done():
			logger.Info("이벤트 처리 종료")
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if err.Error() == "closed" {
					logger.Info("이벤트 리더가 닫혔습니다")
					return
				}
				logger.Debug("이벤트 읽기 오류", "error", err)
				continue
			}

			if len(record.RawSample) < int(unsafe.Sizeof(HTTPRequest{})) {
				logger.Debug("이벤트 데이터 크기 부족", "size", len(record.RawSample))
				continue
			}

			event := (*HTTPRequest)(unsafe.Pointer(&record.RawSample[0]))
			processEvent(event)
		}
	}
}

// 개별 이벤트 처리 (개선된 버전)
func processEvent(event *HTTPRequest) {
	// 통계 업데이트
	updateStats(event)

	method := getHTTPMethod(event.Method)
	path := strings.TrimRight(string(event.Path[:]), "\x00")
	host := strings.TrimRight(string(event.Host[:]), "\x00")
	userAgent := strings.TrimRight(string(event.UserAgent[:]), "\x00")
	remoteAddr := strings.TrimRight(string(event.RemoteAddr[:]), "\x00")

	timestamp := time.Unix(0, int64(event.Timestamp))
	responseTime := time.Duration(event.ResponseTimeNs)

	// 로그 레벨 결정
	logLevel := slog.LevelInfo
	if event.ErrorCode > 0 {
		logLevel = slog.LevelError
	} else if event.StatusCode >= 400 {
		logLevel = slog.LevelWarn
	}

	// 구조화된 로깅
	logger.Log(context.Background(), logLevel, "Kong HTTP 이벤트",
		"timestamp", timestamp.Format("15:04:05.000"),
		"pid", event.PID,
		"tid", event.TID,
		"method", method,
		"path", path,
		"host", host,
		"status_code", event.StatusCode,
		"response_time_ms", float64(responseTime.Nanoseconds())/1e6,
		"user_agent", userAgent,
		"remote_addr", remoteAddr,
		"error_code", event.ErrorCode,
	)

	// JSON 로그 출력 (설정된 경우)
	if config.EnableJSONLog {
		jsonData, _ := json.Marshal(map[string]interface{}{
			"timestamp":     timestamp.UnixNano(),
			"pid":           event.PID,
			"tid":           event.TID,
			"method":        method,
			"path":          path,
			"host":          host,
			"status_code":   event.StatusCode,
			"response_time": event.ResponseTimeNs,
			"user_agent":    userAgent,
			"remote_addr":   remoteAddr,
			"error_code":    event.ErrorCode,
		})
		logger.Debug("JSON 이벤트", "data", string(jsonData))
	}
}

// 상태 출력 (개선된 버전)
func printStatus(ctx context.Context) {
	ticker := time.NewTicker(config.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentStats := getStats()

			logger.Info("=== Kong Gateway 모니터링 상태 ===",
				"total_requests", currentStats.TotalRequests,
				"total_responses", currentStats.TotalResponses,
				"error_count", currentStats.ErrorCount,
				"avg_response_time_ms", float64(currentStats.AvgResponseTime)/1e6,
				"last_request_time", time.Unix(0, currentStats.LastRequestTime).Format("15:04:05"),
				"monitor_pid", os.Getpid(),
			)
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

// 초기화 함수 (Kubernetes 사이드카 환경 최적화)
func initialize() error {
	// 기본 설정 로드
	config = &Config{
		LogLevel:      "info",
		StatsInterval: 30 * time.Second,
		MaxRetries:    3,
		RetryDelay:    5 * time.Second,
		EnableJSONLog: false,
		EnableMetrics: true,
	}

	// 환경 변수에서 설정 로드
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}
	if enableJSON := os.Getenv("ENABLE_JSON_LOG"); enableJSON == "true" {
		config.EnableJSONLog = true
	}
	if statsInterval := os.Getenv("STATS_INTERVAL"); statsInterval != "" {
		if duration, err := time.ParseDuration(statsInterval); err == nil {
			config.StatsInterval = duration
		}
	}

	// 로거 초기화
	var logHandler slog.Handler
	if config.EnableJSONLog {
		logHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: parseLogLevel(config.LogLevel),
		})
	} else {
		logHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: parseLogLevel(config.LogLevel),
		})
	}
	logger = slog.New(logHandler)

	// 사이드카 환경 정보 로깅
	logger.Info("Kong Gateway eBPF Monitor 초기화",
		"log_level", config.LogLevel,
		"json_log", config.EnableJSONLog,
		"stats_interval", config.StatsInterval,
		"kong_process_name", os.Getenv("KONG_PROCESS_NAME"),
	)

	return nil
}

// 정리 함수
func cleanup() {
	logger.Info("리소스 정리 중...")
}

// 로그 레벨 파싱
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// eBPF 객체 로드 함수 (실제 구현)
func loadUprobeObjects(obj *uprobeObjects, opts *ebpf.CollectionOptions) error {
	spec, err := uprobeSpecs()
	if err != nil {
		return fmt.Errorf("eBPF 스펙 로드 실패: %w", err)
	}

	if err := spec.LoadAndAssign(obj, opts); err != nil {
		return fmt.Errorf("eBPF 객체 로드 및 할당 실패: %w", err)
	}

	return nil
}

// eBPF 객체 정리 (개선된 버전)
func (obj *uprobeObjects) Close() error {
	var errs []error

	if obj.UprobeRead != nil {
		if err := obj.UprobeRead.Close(); err != nil {
			errs = append(errs, fmt.Errorf("uprobe_read 닫기 실패: %w", err))
		}
	}
	if obj.UprobeWrite != nil {
		if err := obj.UprobeWrite.Close(); err != nil {
			errs = append(errs, fmt.Errorf("uprobe_write 닫기 실패: %w", err))
		}
	}
	if obj.UprobeKongHttpRequest != nil {
		if err := obj.UprobeKongHttpRequest.Close(); err != nil {
			errs = append(errs, fmt.Errorf("uprobe_kong_http_request 닫기 실패: %w", err))
		}
	}
	if obj.UprobeKongHttpResponse != nil {
		if err := obj.UprobeKongHttpResponse.Close(); err != nil {
			errs = append(errs, fmt.Errorf("uprobe_kong_http_response 닫기 실패: %w", err))
		}
	}
	if obj.UprobeKongLuaHandler != nil {
		if err := obj.UprobeKongLuaHandler.Close(); err != nil {
			errs = append(errs, fmt.Errorf("uprobe_kong_lua_handler 닫기 실패: %w", err))
		}
	}
	if obj.HttpEvents != nil {
		if err := obj.HttpEvents.Close(); err != nil {
			errs = append(errs, fmt.Errorf("http_events 닫기 실패: %w", err))
		}
	}
	if obj.HttpRequests != nil {
		if err := obj.HttpRequests.Close(); err != nil {
			errs = append(errs, fmt.Errorf("http_requests 닫기 실패: %w", err))
		}
	}
	if obj.KongProcesses != nil {
		if err := obj.KongProcesses.Close(); err != nil {
			errs = append(errs, fmt.Errorf("kong_processes 닫기 실패: %w", err))
		}
	}
	if obj.RequestStartTimes != nil {
		if err := obj.RequestStartTimes.Close(); err != nil {
			errs = append(errs, fmt.Errorf("request_start_times 닫기 실패: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("eBPF 객체 정리 중 오류 발생: %v", errs)
	}

	return nil
}

// 통계 업데이트
func updateStats(event *HTTPRequest) {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	atomic.AddInt64(&stats.TotalRequests, 1)
	atomic.StoreInt64(&stats.LastRequestTime, int64(event.Timestamp))

	if event.StatusCode > 0 {
		atomic.AddInt64(&stats.TotalResponses, 1)
		if event.ResponseTimeNs > 0 {
			// 평균 응답 시간 계산 (단순화된 버전)
			currentAvg := atomic.LoadInt64(&stats.AvgResponseTime)
			newAvg := (currentAvg + int64(event.ResponseTimeNs)) / 2
			atomic.StoreInt64(&stats.AvgResponseTime, newAvg)
		}
	}

	if event.ErrorCode > 0 {
		atomic.AddInt64(&stats.ErrorCount, 1)
	}
}

// 통계 조회
func getStats() MonitorStats {
	statsMutex.RLock()
	defer statsMutex.RUnlock()
	return stats
}

// eBPF 스펙 로드 함수 (bpf2go가 생성하는 함수)
func uprobeSpecs() (*ebpf.CollectionSpec, error) {
	// 실제 구현시 bpf2go가 생성하는 코드 사용
	// 여기서는 임시로 nil 반환
	return nil, fmt.Errorf("eBPF 스펙 로드 함수가 구현되지 않았습니다")
}
