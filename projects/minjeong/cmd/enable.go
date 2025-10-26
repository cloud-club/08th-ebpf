package cmd

import (
	"ebpf-firewall/pkg/bpf"
	"fmt"

	"github.com/spf13/cobra"
)

// enableCmd represents the enable command
var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "방화벽 활성화",
	Long:  `방화벽을 활성화하고 eBPF 프로그램을 로드합니다.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := bpf.LoadAndAttach(); err != nil {
			fmt.Printf("Error loading and attaching eBPF program: %v\n", err)
			return
		}
		fmt.Println("✅ Firewall enabled")
	},
}

func init() {
	rootCmd.AddCommand(enableCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// enableCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// enableCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
