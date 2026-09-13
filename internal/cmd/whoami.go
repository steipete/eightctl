package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show configured user ID",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		if err := cl.EnsureUserID(cmd.Context()); err != nil {
			return err
		}
		fmt.Printf("UserID: %s\n", cl.UserID)
		return nil
	},
}
