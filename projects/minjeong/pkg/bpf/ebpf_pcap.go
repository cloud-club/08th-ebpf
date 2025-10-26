package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux ebpf_pcap ebpf_pcap.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	LogFilePath = "/var/log/ebpf.log"
	TCP         = 6
	UDP         = 17
)

type packetEvent struct {
	TsNs      uint64
	Protocol  uint8
	Direction uint8 // 0: egress, 1: ingress
	Sport     uint16
	Dport     uint16
	Saddr     uint32
	Daddr     uint32
}

type PcapCapture struct {
	objs    ebpf_pcapObjects
	links   []link.Link
	rd      *ringbuf.Reader
	logFile *os.File
}

func NewPcapCapture() (*PcapCapture, error) {
	pc := &PcapCapture{}
	logFile, err := os.OpenFile(LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("[경고] 로그 파일 생성 실패 (%s): %v, stdout만 사용", LogFilePath, err)
	} else {
		pc.logFile = logFile
		log.SetOutput(os.Stdout)
		log.SetFlags(log.Ldate | log.Ltime)
	}

	if err := loadEbpf_pcapObjects(&pc.objs, nil); err != nil {
		return nil, fmt.Errorf("eBPF 프로그램 로드 실패: %w", err)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		pc.objs.Close()
		return nil, fmt.Errorf("네트워크 인터페이스 조회 실패: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		lIngress, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   pc.objs.HandlePacket,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			log.Printf("[경고] %s ingress hook 연결 실패: %v", iface.Name, err)
		} else {
			pc.links = append(pc.links, lIngress)
			log.Printf("[+] %s ingress hook 연결 성공", iface.Name)
		}

		lEgress, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   pc.objs.HandlePacket,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			log.Printf("[경고] %s egress hook 연결 실패: %v", iface.Name, err)
		} else {
			pc.links = append(pc.links, lEgress)
			log.Printf("[+] %s egress hook 연결 성공", iface.Name)
		}
	}

	if len(pc.links) == 0 {
		pc.objs.Close()
		return nil, fmt.Errorf("어떤 인터페이스에도 연결할 수 없습니다")
	}

	rd, err := ringbuf.NewReader(pc.objs.Events)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("ringbuf 리더 생성 실패: %w", err)
	}

	pc.rd = rd
	return pc, nil
}

func (pc *PcapCapture) Start() error {
	fmt.Println("[+] eBPF packet capture started...")
	if pc.logFile != nil {
		pc.logFile.WriteString(fmt.Sprintf("[%s] [+] eBPF packet capture started...\n",
			time.Now().Format("2006-01-02 15:04:05")))
	}

	for {
		record, err := pc.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("ringbuf 읽기 오류: %v", err)
			continue
		}

		var event packetEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("이벤트 파싱 실패: %v", err)
			continue
		}

		protoStr := "UNKNOWN"
		if event.Protocol == TCP {
			protoStr = "TCP"
		} else if event.Protocol == UDP {
			protoStr = "UDP"
		}

		directionStr := "egress"
		if event.Direction == 1 {
			directionStr = "ingress"
		}

		msg := fmt.Sprintf("Captured packet[%s]: %s %s:%d -> %s:%d",
			directionStr,
			protoStr,
			intToIP(event.Saddr), event.Sport,
			intToIP(event.Daddr), event.Dport,
		)

		fmt.Println(msg)
		if pc.logFile != nil {
			if _, err := pc.logFile.WriteString(fmt.Sprintf("[%s] %s\n",
				time.Now().Format("2006-01-02 15:04:05"), msg)); err != nil {
				log.Printf("[경고] 로그 파일 쓰기 실패: %v", err)
			}
		}
	}
}

func (pc *PcapCapture) Close() {
	fmt.Println("[!] Detaching eBPF programs from interfaces...")
	for _, l := range pc.links {
		l.Close()
	}

	fmt.Println("[!] All interfaces detached.")
	if pc.rd != nil {
		pc.rd.Close()
	}

	pc.objs.Close()
	if pc.logFile != nil {
		pc.logFile.WriteString(fmt.Sprintf("[%s] [!] eBPF packet capture stopped.\n",
			time.Now().Format("2006-01-02 15:04:05")))
		pc.logFile.Close()
	}
}

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
