package cmd

import (
	"ebpf-firewall/pkg/bpf"
	"fmt"

	"github.com/spf13/cobra"
)

// disableCmd represents the disable command
var disableCmd = &cobra.Command{
	Use:   "disable",
	Short: "방화벽 비활성화",
	Long:  `방화벽을 비활성화하고 eBPF 프로그램을 언로드합니다.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := bpf.Detach(); err != nil {
			fmt.Printf("Error loading and attaching eBPF program: %v\n", err)
			return
		}
		fmt.Println("✅ Firewall disabled")
	},
}

func init() {
	rootCmd.AddCommand(disableCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// disableCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// disableCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
