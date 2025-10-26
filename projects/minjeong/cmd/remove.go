/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"ebpf-firewall/pkg/policy"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

var removeCmd = &cobra.Command{
	Use:   "remove [number]",
	Short: "방화벽 규칙을 삭제합니다",
	Long:  "지정한 번호의 방화벽 규칙을 삭제합니다.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		index, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Printf("잘못된 규칙 번호입니다: %v\n", err)
			return
		}

		if err := policy.RemoveRule(index); err != nil {
			fmt.Printf("규칙 삭제 실패: %v\n", err)
			return
		}

		fmt.Printf("규칙 [%d]이(가) 삭제되었습니다.\n", index)
	},
}

func init() {
	rootCmd.AddCommand(removeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// removeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// removeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
