package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
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

var awayStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether away mode is active",
	Long: "Report away mode per household user.\n\n" +
		"This cannot be inferred from `eightctl status`: the temperature schedule is\n" +
		"unaffected by away mode, so it reads the same either way.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		ctx := context.Background()

		targets, all, err := resolveCommandTargets(ctx, cmd, cl)
		if err != nil {
			return err
		}
		both, _ := cmd.Flags().GetBool("both")
		if both && !all {
			targets, err = cl.HouseholdUserTargets(ctx)
			if err != nil {
				return fmt.Errorf("listing household users: %w", err)
			}
			all = true
		}

		rows := []map[string]any{}
		if !all && len(targets) == 0 {
			away, err := cl.GetAwayMode(ctx, "")
			if err != nil {
				return err
			}
			rows = append(rows, map[string]any{"away": away})
			return printAwayRows([]string{"away"}, rows)
		}
		for _, t := range targets {
			away, err := cl.GetAwayMode(ctx, t.UserID)
			if err != nil {
				return fmt.Errorf("reading away mode for %s: %w", t.UserID, err)
			}
			rows = append(rows, map[string]any{
				"side":    t.Side,
				"name":    strings.TrimSpace(t.FirstName + " " + t.LastName),
				"user_id": t.UserID,
				"away":    away,
			})
		}
		return printAwayRows([]string{"side", "name", "user_id", "away"}, rows)
	},
}

func printAwayRows(headers []string, rows []map[string]any) error {
	fields := viper.GetStringSlice("fields")
	rows = output.FilterFields(rows, fields)
	if len(fields) > 0 {
		headers = fields
	}
	return output.Print(output.Format(viper.GetString("output")), headers, rows)
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
		scope = "both sides"
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
	addTargetingFlags(awayStatusCmd, true)
	awayStatusCmd.Flags().Bool("all-sides", false, "show away mode for all discovered household sides")
	awayCmd.AddCommand(awayOnCmd)
	awayCmd.AddCommand(awayOffCmd)
	awayCmd.AddCommand(awayStatusCmd)
}
