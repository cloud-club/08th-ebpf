package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// 구조체는 BPF C 코드에서 정의한 것과 동일하게 맞춰야 합니다
type cpuEvent struct {
	LastTimestamp uint64
	TotalTimeNs   uint64
}

type faultEvent struct {
	UserFaults   uint64
	KernelFaults uint64
}

func main() {
	// 1️⃣ BPF 오브젝트 로드
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
	pfMap := coll.Maps["page_faults"]

	// 2️⃣ tracepoint attach
	if _, err := link.Tracepoint("sched", "sched_switch", coll.Programs["handle_sched_switch"], nil); err != nil {
		log.Fatalf("failed to attach sched_switch: %v", err)
	}

	if _, err := link.Tracepoint("exceptions", "page_fault_user", coll.Programs["handle_page_fault_user"], nil); err != nil {
		log.Fatalf("failed to attach page_fault_user: %v", err)
	}

	if _, err := link.Tracepoint("exceptions", "page_fault_kernel", coll.Programs["handle_page_fault_kernel"], nil); err != nil {
		log.Fatalf("failed to attach page_fault_kernel: %v", err)
	}

	fmt.Println("BPF programs attached. Collecting metrics...")

	// 3️⃣ 주기적으로 map 읽어서 출력
	for {
		fmt.Println("----- CPU Usage -----")
		var pid uint32
		var evt cpuEvent
		iter := cpuMap.Iterate()
		for iter.Next(&pid, &evt) {
			fmt.Printf("PID: %d, CPU time: %.6f sec\n", pid, float64(evt.TotalTimeNs)/1e9)
		}

		fmt.Println("----- Page Faults -----")
		var pfEvt faultEvent
		iter2 := pfMap.Iterate()
		for iter2.Next(&pid, &pfEvt) {
			fmt.Printf("PID: %d, User faults: %d, Kernel faults: %d\n", pid, pfEvt.UserFaults, pfEvt.KernelFaults)
		}

		time.Sleep(2 * time.Second)
	}
}

