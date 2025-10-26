package cmd

import (
	"ebpf-firewall/pkg/bpf"
	"ebpf-firewall/pkg/policy"
	"ebpf-firewall/pkg/rule"
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "방화벽의 활성화/비활성화 상태를 확인합니다",
	Long:  "현재 eBPF 방화벽이 활성화되어 있는지 비활성화되어 있는지 상태를 확인합니다.",
	Run: func(cmd *cobra.Command, args []string) {
		if !bpf.IsActive() {
			fmt.Println("방화벽 상태: 비활성화됨 ✗")
			return
		}

		fmt.Println("방화벽 상태: 활성화됨 ✓")

		// 규칙 개수
		rules := policy.GetAllRules()
		fmt.Printf("활성 규칙: %d개\n", len(rules))

		// 기본 정책
		inbound, err1 := bpf.GetDefaultPolicy(rule.DirectionInbound)
		outbound, err2 := bpf.GetDefaultPolicy(rule.DirectionOutbound)

		if err1 == nil && err2 == nil {
			fmt.Printf("기본 정책: IN=%s, OUT=%s\n",
				inbound.String(), outbound.String())
		}
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// statusCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// statusCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
