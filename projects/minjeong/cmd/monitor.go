package cmd

import (
	"ebpf-firewall/pkg/bpf"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "패킷 캡처 모니터링을 시작합니다",
	Long:  "방화벽을 통과하는 패킷을 실시간으로 모니터링합니다.",
	Run: func(cmd *cobra.Command, args []string) {
		// 패킷 캡처 초기화
		capture, err := bpf.NewPcapCapture()
		if err != nil {
			log.Fatalf("캡처 초기화 실패: %v", err)
		}
		defer capture.Close()

		// 시그널 핸들링 설정
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

		// 패킷 캡처 시작 (고루틴)
		go func() {
			if err := capture.Start(); err != nil {
				log.Printf("캡처 실행 오류: %v", err)
			}
		}()

		fmt.Println("[+] eBPF 패킷 캡처가 시작되었습니다.")
		fmt.Println("[*] 중지하려면 Ctrl+C를 누르세요.")

		// 시그널 대기
		<-sig
		fmt.Println("\n[!] eBPF 패킷 캡처가 중지되었습니다.")
	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// monitorCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// monitorCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
