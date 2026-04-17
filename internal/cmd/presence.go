package cmd

import (
	"context"
	"fmt"
	"time"

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
		from, err := cmd.Flags().GetString("from")
		if err != nil {
			return err
		}
		to, err := cmd.Flags().GetString("to")
		if err != nil {
			return err
		}
		if err := validatePresenceDateRange(from, to); err != nil {
			return err
		}
		tz, err := resolveAPITimezone(viper.GetString("timezone"))
		if err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		present, err := cl.GetPresence(context.Background(), from, to, tz)
		if err != nil {
			return err
		}
		return output.Print(output.Format(viper.GetString("output")), []string{"present"}, []map[string]any{{"present": present}})
	},
}

func validatePresenceDateRange(from, to string) error {
	const layout = "2006-01-02"

	if from != "" {
		if _, err := time.Parse(layout, from); err != nil {
			return fmt.Errorf("invalid --from date %q: %w", from, err)
		}
	}
	if to != "" {
		if _, err := time.Parse(layout, to); err != nil {
			return fmt.Errorf("invalid --to date %q: %w", to, err)
		}
	}
	if from != "" && to != "" && to < from {
		return fmt.Errorf("--to must be >= --from")
	}
	return nil
}

func init() {
	presenceCmd.Flags().String("from", "", "from date YYYY-MM-DD")
	presenceCmd.Flags().String("to", "", "to date YYYY-MM-DD")
}
