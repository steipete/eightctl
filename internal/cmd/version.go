package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version = "0.2.8"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(Version)
	},
}
