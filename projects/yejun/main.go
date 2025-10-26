package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// CPU 이벤트 구조체 (BPF와 동일하게)
type cpuEvent struct {
	LastTimestamp uint64
	TotalTimeNs   uint64
	SwitchCount   uint64
	CPUburst      uint32
	IOburst       uint32
}

// PID의 command 이름을 가져오는 함수
func getCmdName(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return string(data[:len(data)-1]) // 마지막 \n 제거
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	// BPF 오브젝트 로드
	spec, err := ebpf.LoadCollectionSpec("bpf/cpu_mem_monitor.bpf.o")
	if err != nil {
		log.Fatalf("failed to load BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	cpuMap := coll.Maps["cpu_usage"]

	// tracepoint attach
	tp, err := link.Tracepoint("sched", "sched_switch", coll.Programs["handle_sched_switch"], nil)
	if err != nil {
		log.Fatalf("failed to attach sched_switch: %v", err)
	}
	defer tp.Close()

	numCPUs := runtime.NumCPU()
	fmt.Printf("✅ eBPF program loaded. Monitoring sched_switch... (%d CPUs)\n", numCPUs)

	interval := 5 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Ctrl+C 처리
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			fmt.Println("------ CPU/I/O Burst (last 5s) ------")

			printed := make(map[uint32]bool)
			var pid uint32 = 0
			for {
				var nextPID uint32
				if err := cpuMap.NextKey(pid, &nextPID); err != nil {
					break
				}

				if printed[nextPID] {
					pid = nextPID
					continue
				}
				printed[nextPID] = true

				var evt cpuEvent
				if err := cpuMap.Lookup(nextPID, &evt); err != nil {
					pid = nextPID
					continue
				}
				total := evt.SwitchCount
                		if total == 0 {
                    			continue
                		}
                		ioRatio := float64(evt.IOburst) / float64(total) * 100
				burstType := "I/O-bound"
                		if ioRatio < 30 { // IO-burst 비율이 30% 미만이면 CPU-bound
                  	  		burstType = "CPU-bound"
                		}

				cpuUsageRatio := float64(evt.TotalTimeNs) / (float64(interval.Nanoseconds()) * float64(numCPUs)) * 100
				cmd := getCmdName(nextPID)

				// CPU 40 % 점유 시 출력
				if cpuUsageRatio > 40 {
					fmt.Printf("[%s] I/O Switches: %-6d PID %-6d CMD: (%-15s) | CPU: %6.2f%% | Switches: %-5d\n",
						burstType, evt.IOburst, nextPID, cmd, cpuUsageRatio * float64(numCPUs), evt.SwitchCount)
				}

				// map 초기화
				if err := cpuMap.Delete(nextPID); err != nil {
					log.Printf("failed to delete PID %d: %v", nextPID, err)
				}

				pid = nextPID
			}

			fmt.Println("-------------------------------------")

		case <-sig:
			fmt.Println("Exiting...")
			return
		}
	}
}

