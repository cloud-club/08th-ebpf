/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"ebpf-firewall/pkg/bpf"
	"ebpf-firewall/pkg/rule"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var defaultCmd = &cobra.Command{
	Use:   "default [allow|deny] [in|out]",
	Short: "기본 정책을 설정하거나 조회합니다",
	Long:  "인자가 없으면 현재 기본 정책을 조회하고, 인자가 있으면 기본 정책을 변경합니다.",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			// 기본 설정 조회
			inboundAction, err := bpf.GetDefaultPolicy(rule.DirectionInbound)
			if err != nil {
				fmt.Printf("인바운드 기본 정책 조회 실패: %v\n", err)
				return
			}

			outboundAction, err := bpf.GetDefaultPolicy(rule.DirectionOutbound)
			if err != nil {
				fmt.Printf("아웃바운드 기본 정책 조회 실패: %v\n", err)
				return
			}

			fmt.Printf("기본 정책:\n")
			fmt.Printf("  인바운드: %s\n", inboundAction.String())
			fmt.Printf("  아웃바운드: %s\n", outboundAction.String())
			return
		}

		if len(args) != 2 {
			fmt.Println("사용법: ebpfw default [allow|deny] [in|out]")
			return
		}

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

		// Direction 파싱
		var direction rule.Direction
		switch strings.ToLower(args[1]) {
		case "in":
			direction = rule.DirectionInbound
		case "out":
			direction = rule.DirectionOutbound
		default:
			fmt.Println("허용되지 않은 방향입니다. 'in' 또는 'out'을 사용하세요.")
			return
		}

		// 기본 정책 설정
		if err := bpf.SetDefaultPolicy(direction, action); err != nil {
			fmt.Printf("기본 정책 설정 실패: %v\n", err)
			return
		}

		fmt.Printf("%s 기본 정책이 %s(으)로 설정되었습니다.\n",
			direction.String(), action.String())
	},
}

func init() {
	rootCmd.AddCommand(defaultCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// defaultCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// defaultCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
