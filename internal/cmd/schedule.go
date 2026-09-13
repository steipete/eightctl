package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Show the Autopilot (smart) schedule",
}

var scheduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show the Autopilot schedule for the current user",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		smart, err := cl.GetSmartSchedule(context.Background())
		if err != nil {
			if errors.Is(err, client.ErrNoSmartSchedule) {
				fmt.Fprintln(cmd.OutOrStdout(), "no Autopilot schedule configured for this user")
				return nil
			}
			return err
		}
		return printRows([]string{"smart"}, []map[string]any{{"smart": smart}})
	},
}

func init() {
	scheduleCmd.AddCommand(scheduleListCmd)
}
