package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ebpf-route/internal/config"
	"ebpf-route/pkg/ebpf"
	"ebpf-route/pkg/routing"

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
	fmt.Printf("🚀 eBPF Router %s\n", version)

	// root 권한 확인
	if os.Geteuid() != 0 {
		log.Fatal("eBPF 프로그램을 로드하려면 root 권한이 필요합니다")
	}

	// 설정 파일 로드
	fmt.Printf("설정 파일 로드: %s\n", configFile)
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatalf("설정 로드 실패: %v", err)
	}

	// 라우팅 테이블 생성
	routingTable := routing.NewTable(cfg.Router.MaxRules)

	// eBPF 관리자 생성
	ebpfManager, err := ebpf.NewManager(cfg, routingTable)
	if err != nil {
		log.Fatalf("eBPF 관리자 생성 실패: %v", err)
	}

	// 라우터 시작
	if err := ebpfManager.Start(); err != nil {
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
	if err := ebpfManager.Stop(); err != nil {
		log.Printf("라우터 정리 중 오류: %v", err)
	}

	fmt.Println("라우터가 정상적으로 종료되었습니다.")
}
