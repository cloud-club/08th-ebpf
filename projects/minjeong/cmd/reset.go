/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"ebpf-firewall/pkg/policy"
	"fmt"

	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "모든 방화벽 규칙을 삭제합니다",
	Long:  "설정된 모든 방화벽 규칙을 초기화하고 삭제합니다.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := policy.ResetRules(); err != nil {
			fmt.Printf("규칙 초기화 실패: %v\n", err)
			return
		}

		fmt.Println("모든 방화벽 규칙이 삭제되었습니다.")
	},
}

func init() {
	rootCmd.AddCommand(resetCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// resetCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// resetCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
