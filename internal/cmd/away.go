package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var awayCmd = &cobra.Command{
	Use:   "away",
	Short: "Away mode (vacation)",
	Long:  "Activate or deactivate away mode. When away, the pod stops heating/cooling.\nDefaults to the authenticated user's side. Use --both for both sides.",
}

var awayOnCmd = &cobra.Command{
	Use:   "on",
	Short: "Activate away mode",
	RunE:  func(cmd *cobra.Command, args []string) error { return runAway(true) },
}

var awayOffCmd = &cobra.Command{
	Use:   "off",
	Short: "Deactivate away mode",
	RunE:  func(cmd *cobra.Command, args []string) error { return runAway(false) },
}

func runAway(on bool) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	ctx := context.Background()
	both, _ := awayCmd.Flags().GetBool("both")

	if both {
		sides, err := cl.Device().Sides(ctx)
		if err != nil {
			return fmt.Errorf("fetching device sides: %w", err)
		}
		for _, uid := range []string{sides.LeftUserID, sides.RightUserID} {
			if uid == "" {
				continue
			}
			if err := cl.SetAwayMode(ctx, uid, on); err != nil {
				return fmt.Errorf("setting away for %s: %w", uid, err)
			}
		}
	} else {
		if err := cl.SetAwayMode(ctx, "", on); err != nil {
			return err
		}
	}

	action := "activated"
	if !on {
		action = "deactivated"
	}
	scope := "your side"
	if both {
		scope = "both sides"
	}
	fmt.Printf("away mode %s (%s)\n", action, scope)
	return nil
}

func init() {
	awayCmd.PersistentFlags().Bool("both", false, "Apply to both sides of the pod")
	awayCmd.AddCommand(awayOnCmd)
	awayCmd.AddCommand(awayOffCmd)
}
