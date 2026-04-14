package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
)

var presenceCmd = &cobra.Command{
	Use:   "presence",
	Short: "Check if user is in bed",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		tz, err := resolveAPITimezone(viper.GetString("timezone"))
		if err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		present, err := cl.GetPresence(context.Background(), tz)
		if err != nil {
			return err
		}
		return output.Print(output.Format(viper.GetString("output")), []string{"present"}, []map[string]any{{"present": present}})
	},
}
