package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ebpf-firewall/internal/bpf"
)

func main() {
	capture, err := bpf.NewPcapCapture()
	if err != nil {
		log.Fatalf("캡처 초기화 실패: %v", err)
	}
	defer capture.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := capture.Start(); err != nil {
			log.Printf("캡처 실행 오류: %v", err)
		}
	}()

	<-sig
	fmt.Println("\n[!] eBPF packet capture stopped.")
}
