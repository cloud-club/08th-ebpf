package cmd

import (
	"ebpf-firewall/pkg/policy"
	"ebpf-firewall/pkg/rule"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add [allow|deny] [port] [protocol] [in|out] [ip]",
	Short: "방화벽 규칙을 추가합니다",
	Long:  "새로운 방화벽 규칙을 추가합니다. 포트, 프로토콜, 방향은 필수이며 IP는 선택사항입니다.",
	Args:  cobra.MinimumNArgs(4),
	Run: func(cmd *cobra.Command, args []string) {
		// Action 파싱
		var action rule.Action
		switch strings.ToLower(args[0]) {
		case "allow":
			action = rule.ActionAllow
		case "deny":
			action = rule.ActionDeny
		default:
			fmt.Println("허용되지 않은 액션입니다. 'allow' 또는 'deny'를 사용하세요.")
			return
		}

		// Port 파싱
		port, err := strconv.ParseUint(args[1], 10, 16)
		if err != nil {
			fmt.Printf("포트 파싱 실패: %v\n", err)
			return
		}

		// Protocol 파싱
		var protocol rule.Protocol
		switch strings.ToLower(args[2]) {
		case "tcp":
			protocol = rule.ProtocolTCP
		case "udp":
			protocol = rule.ProtocolUDP
		case "any":
			protocol = rule.ProtocolAny
		default:
			fmt.Println("허용되지 않은 프로토콜입니다. 'tcp', 'udp', 'any'를 사용하세요.")
			return
		}

		// Direction 파싱
		var direction rule.Direction
		switch strings.ToLower(args[3]) {
		case "in":
			direction = rule.DirectionInbound
		case "out":
			direction = rule.DirectionOutbound
		default:
			fmt.Println("허용되지 않은 방향입니다. 'in' 또는 'out'을 사용하세요.")
			return
		}

		// IP 파싱 (선택사항)
		// TODO: 수정 필요!!!!
		var srcIP, dstIP uint32 = 0, 0
		if len(args) > 4 {
			ipAddr, err := rule.IPToUint32(args[4]) // ip 대신 ipAddr 사용
			if err != nil {
				fmt.Printf("IP 주소 파싱 실패: %v\n", err)
				return
			}

			// Direction에 따라 src/dst 결정
			if direction == rule.DirectionInbound {
				srcIP = ipAddr // 인바운드는 소스 IP
			} else {
				dstIP = ipAddr // 아웃바운드는 목적지 IP
			}
		}

		// Rule 생성 및 추가
		newRule := &rule.Rule{
			Port:      uint16(port),
			Protocol:  protocol,
			Direction: direction,
			Action:    action,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Valid:     1,
		}

		if err := policy.AddRule(newRule); err != nil {
			fmt.Printf("규칙 추가 실패: %v\n", err)
			return
		}

		fmt.Printf("규칙이 추가되었습니다: %s\n", newRule.String())
	},
}

func init() {
	rootCmd.AddCommand(addCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// addCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// addCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
