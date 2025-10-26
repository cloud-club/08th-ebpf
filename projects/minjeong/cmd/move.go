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

var moveCmd = &cobra.Command{
	Use:   "move [from] [to]",
	Short: "방화벽 규칙의 순서를 변경합니다",
	Long:  "방화벽 규칙을 from 위치에서 to 위치로 이동시킵니다.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		from, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Printf("잘못된 from 번호입니다: %v\n", err)
			return
		}

		to, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Printf("잘못된 to 번호입니다: %v\n", err)
			return
		}

		if err := policy.MoveRule(from, to); err != nil {
			fmt.Printf("규칙 이동 실패: %v\n", err)
			return
		}

		fmt.Printf("규칙 [%d]이(가) [%d](으)로 이동되었습니다.\n", from, to)
	},
}

func init() {
	rootCmd.AddCommand(moveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// moveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// moveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
