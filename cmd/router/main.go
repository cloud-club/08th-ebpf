package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ebpf-route/internal/config"
	"github.com/spf13/cobra"
)

var (
	version    = "v0.1.0"
	configFile string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("실행 오류: %v", err)
	}
}

var rootCmd = &cobra.Command{
	Use:   "ebpf-router",
	Short: "eBPF 기반 패킷 라우터",
	Long:  `eBPF XDP를 사용하여 패킷 라우팅을 수행합니다.`,
	Run:   runRouter,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "버전 정보",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ebpf-router %s\n", version)
	},
}

func init() {
	// 플래그 설정
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.yaml", "설정 파일 경로")
	rootCmd.AddCommand(versionCmd)
}

func runRouter(cmd *cobra.Command, args []string) {
	fmt.Printf("eBPF Router %s 시작 중...\n", version)

	// root 권한 확인
	if os.Geteuid() != 0 {
		log.Fatal("eBPF 프로그램을 로드하려면 root 권한이 필요합니다 (sudo 사용)")
	}

	// 설정 파일 로드
	fmt.Printf("설정 파일 로드 중: %s\n", configFile)
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatalf("설정 로드 실패: %v", err)
	}

	// eBPF 라우터 생성 및 시작
	router, err := NewEBPFRouter(cfg)
	if err != nil {
		log.Fatalf("라우터 생성 실패: %v", err)
	}

	if err := router.Start(); err != nil {
		log.Fatalf("라우터 시작 실패: %v", err)
	}

	fmt.Println("라우터가 성공적으로 시작되었습니다!")
	fmt.Println("종료하려면 Ctrl+C를 누르세요")

	// 시그널 채널 생성
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 시그널 대기
	<-sigChan

	// 라우터 정리 작업
	if err := router.Stop(); err != nil {
		log.Printf("라우터 정리 중 오류: %v", err)
	}

	fmt.Println("라우터가 정상적으로 종료되었습니다.")
}

// EBPFRouter는 eBPF 라우터의 메인 구조체입니다
type EBPFRouter struct {
	config *config.Config
}

// NewEBPFRouter는 새로운 eBPF 라우터를 생성합니다
func NewEBPFRouter(cfg *config.Config) (*EBPFRouter, error) {
	return &EBPFRouter{
		config: cfg,
	}, nil
}

// Start는 라우터를 시작합니다
func (r *EBPFRouter) Start() error {
	fmt.Println("eBPF 프로그램 로딩 중...")
	// TODO: 실제 eBPF 프로그램 로드

	fmt.Println("라우팅 규칙 설정 중...")
	// TODO: 라우팅 규칙 맵에 로드

	fmt.Printf("인터페이스 '%s'에 XDP 프로그램 연결 중...\n", r.config.Network.Interface)
	// TODO: XDP 프로그램을 네트워크 인터페이스에 연결

	return nil
}

// Stop은 라우터를 정리하고 종료합니다
func (r *EBPFRouter) Stop() error {
	fmt.Println("eBPF 프로그램 정리 중...")
	// TODO: eBPF 프로그램 언로드

	fmt.Println("라우팅 규칙 정리 중...")
	// TODO: 라우팅 규칙 맵 정리

	fmt.Printf("인터페이스 '%s'에서 XDP 프로그램 분리 중...\n", r.config.Network.Interface)
	// TODO: XDP 프로그램을 네트워크 인터페이스에서 분리

	return nil
}
