package cmd

import "github.com/spf13/cobra"

var offCmd = &cobra.Command{
	Use:   "off",
	Short: "Turn pod off",
	RunE:  func(cmd *cobra.Command, args []string) error { return runPower(cmd, false) },
}

func init() {
	addTargetingFlags(offCmd, true)
}
