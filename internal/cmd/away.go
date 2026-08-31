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
	Long:  "Activate or deactivate away mode. When away, the pod stops heating/cooling.\nTarget a specific side with --side left|right|solo, a specific user with\n--target-user-id, or apply to every household member with --both.\nWith no flags, defaults to the authenticated user's side.",
}

var awayOnCmd = &cobra.Command{
	Use:   "on",
	Short: "Activate away mode",
	RunE:  func(cmd *cobra.Command, args []string) error { return runAway(cmd, true) },
}

var awayOffCmd = &cobra.Command{
	Use:   "off",
	Short: "Deactivate away mode",
	RunE:  func(cmd *cobra.Command, args []string) error { return runAway(cmd, false) },
}

func runAway(cmd *cobra.Command, on bool) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	ctx := context.Background()
	both, _ := cmd.Flags().GetBool("both")

	target, err := resolveSelectedTarget(ctx, cmd, cl)
	if err != nil {
		return err
	}

	action := "activated"
	if !on {
		action = "deactivated"
	}
	var scope string

	switch {
	case both:
		if target != nil {
			return fmt.Errorf("--both conflicts with --side/--target-user-id")
		}
		// Deliberately NOT Device().Sides(): when every household member is
		// already away, the device payload omits leftUserId/rightUserId, so
		// Sides() returns empty strings. The old loop skipped both and made
		// zero requests while still reporting success, which meant
		// `away off --both` could never bring an all-away household home.
		targets, err := cl.HouseholdUserTargets(ctx)
		if err != nil {
			return fmt.Errorf("fetching household users: %w", err)
		}
		if len(targets) == 0 {
			return fmt.Errorf("no household users found")
		}
		for _, current := range targets {
			if current.UserID == "" {
				continue
			}
			if err := cl.SetAwayMode(ctx, current.UserID, on); err != nil {
				return fmt.Errorf("setting away for %s: %w", current.UserID, err)
			}
		}
		scope = fmt.Sprintf("%d household members", len(targets))
	case target != nil:
		if err := cl.SetAwayMode(ctx, target.UserID, on); err != nil {
			return fmt.Errorf("setting away for %s: %w", target.UserID, err)
		}
		scope = targetScope(target)
		if scope == "" {
			scope = "selected target"
		}
	default:
		if err := cl.SetAwayMode(ctx, "", on); err != nil {
			return err
		}
		scope = "your side"
	}

	if !viper.GetBool("quiet") {
		fmt.Printf("away mode %s (%s)\n", action, scope)
	}
	return nil
}

func init() {
	awayCmd.PersistentFlags().Bool("both", false, "Apply to every household member")
	addTargetingFlags(awayOnCmd, true)
	addTargetingFlags(awayOffCmd, true)
	awayCmd.AddCommand(awayOnCmd)
	awayCmd.AddCommand(awayOffCmd)
}
