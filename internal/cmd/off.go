package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var offCmd = &cobra.Command{
	Use:   "off",
	Short: "Turn pod off",
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
				if err := cl.TurnOffForUser(context.Background(), target.UserID); err != nil {
					return err
				}
			}
			fmt.Printf("pod turned off%s\n", targetListSuffix(targets))
			return nil
		}

		if err := cl.TurnOffForUser(context.Background(), ""); err != nil {
			return err
		}
		fmt.Printf("pod turned off\n")
		return nil
	},
}

func init() {
	addTargetingFlags(offCmd, true)
}
