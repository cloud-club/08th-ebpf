package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ebpfw",
	Short: "eBPF 기반 호스트 방화벽",
	Long: `ebpfw는 eBPF/TC를 사용하는 호스트 방화벽입니다.

간단한 CLI로 방화벽 규칙을 관리할 수 있습니다.

Examples:
  ebpfw enable
  ebpfw add allow 22 tcp in
  ebpfw list`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
}
