/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"ebpf-firewall/pkg/policy"
	"fmt"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "방화벽 규칙 목록을 출력합니다",
	Long:  "현재 설정된 모든 방화벽 규칙을 번호와 함께 출력합니다.",
	Run: func(cmd *cobra.Command, args []string) {
		rules := policy.GetAllRules()
		if len(rules) == 0 {
			fmt.Println("설정된 규칙이 없습니다.")
			return
		}

		fmt.Println("방화벽 규칙 목록:")
		for i, rule := range rules {
			fmt.Printf("[%d] %s\n", i, rule.String())
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
