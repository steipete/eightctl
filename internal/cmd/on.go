package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var onCmd = &cobra.Command{
	Use:   "on",
	Short: "Turn pod on",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		targets, targeted, err := resolveCommandTargets(context.Background(), cmd, cl)
		if err != nil {
			return err
		}
		if targeted {
			for _, target := range targets {
				if err := cl.TurnOnForUser(context.Background(), target.UserID); err != nil {
					return err
				}
			}
			fmt.Printf("pod turned on%s\n", targetListSuffix(targets))
			return nil
		}

		if err := cl.TurnOnForUser(context.Background(), ""); err != nil {
			return err
		}
		fmt.Printf("pod turned on\n")
		return nil
	},
}

func init() {
	addTargetingFlags(onCmd, true)
}
