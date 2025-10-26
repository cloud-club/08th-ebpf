package rule

import (
	"fmt"
	"strconv"
	"strings"
)

type Action uint8
type Protocol uint8
type Direction uint8

const (
	ActionDeny  Action = 0
	ActionAllow Action = 1

	ProtocolAny Protocol = 0
	ProtocolTCP Protocol = 6
	ProtocolUDP Protocol = 17

	DirectionInbound  Direction = 0
	DirectionOutbound Direction = 1
)

type Rule struct {
	SrcIP     uint32
	DstIP     uint32
	Port      uint16
	Protocol  Protocol
	Direction Direction
	Action    Action
	Valid     uint8 // 1 = 활성, 0 = 비활성
}

func (r *Rule) String() string {
	return fmt.Sprintf("%s port %d %s %s",
		r.ActionString(), r.Port, r.ProtocolString(), r.DirectionString())
}

func (a Action) String() string {
	if a == ActionAllow {
		return "allow"
	}
	return "deny"
}

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	default:
		return "any"
	}
}

func (d Direction) String() string {
	if d == DirectionInbound {
		return "in"
	}
	return "out"
}

// ebpf_fw_rule.go에서 헬퍼 메서드들을 여기에 추가
func (r *Rule) ActionString() string {
	return r.Action.String()
}

func (r *Rule) ProtocolString() string {
	return r.Protocol.String()
}

func (r *Rule) DirectionString() string {
	return r.Direction.String()
}

// IPToUint32는 IPv4 주소 문자열을 uint32로 변환
func IPToUint32(ipStr string) (uint32, error) {
	octets := strings.Split(ipStr, ".")
	if len(octets) != 4 {
		return 0, fmt.Errorf("잘못된 IP 주소 형식입니다: %s", ipStr)
	}

	var ip uint32
	for i, octet := range octets {
		val, err := strconv.ParseUint(octet, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("잘못된 옥텟 값입니다: %s", octet)
		}
		if val > 255 {
			return 0, fmt.Errorf("옥텟 값은 0-255 사이여야 합니다: %d", val)
		}
		// 빅엔디안 방식으로 변환
		ip |= uint32(val) << (24 - uint(i*8))
	}

	return ip, nil
}

// Uint32ToIP는 uint32를 IPv4 주소 문자열로 변환
func Uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF,
	)
}
