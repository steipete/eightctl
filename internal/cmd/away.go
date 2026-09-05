package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
)

var awayCmd = &cobra.Command{
	Use:   "away",
	Short: "Away mode (vacation)",
	Long: "When away, the pod stops heating/cooling.\n" +
		"'away on' and 'away off' default to the authenticated user's side;\n" +
		"use --both to update every household member. 'away status' reports\n" +
		"all discovered household sides by default. Use --side left|right|solo\n" +
		"or --target-user-id to select one person for any subcommand.\n" +
		"The cloud is eventually consistent: status may show the previous state\n" +
		"after a write and does not immediately confirm that a change took effect.",
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
	Args:  cobra.NoArgs,
	Long: "Report away mode for each household side. Narrow to one person with\n" +
		"--side left|right|solo or --target-user-id. Unlike 'away on' and 'away off',\n" +
		"this reads all discovered household sides by default.\n" +
		"The cloud is eventually consistent: status may show the previous state\n" +
		"after a write and does not immediately confirm that a change took effect.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		return runAwayStatusWithClient(context.Background(), cmd, cl)
	},
}

func runAwayStatusWithClient(ctx context.Context, cmd *cobra.Command, cl *client.Client) error {
	both, _ := cmd.Flags().GetBool("both")
	side, _ := cmd.Flags().GetString("side")
	userID, _ := cmd.Flags().GetString("target-user-id")
	if both && (side != "" || userID != "") {
		return fmt.Errorf("--both conflicts with --side/--target-user-id")
	}
	target, err := resolveSelectedTarget(ctx, cmd, cl)
	if err != nil {
		return err
	}

	var targets []client.HouseholdUserTarget
	if target != nil {
		targets = []client.HouseholdUserTarget{*target}
	} else {
		targets, err = cl.HouseholdUserTargets(ctx)
		if err != nil {
			return err
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no household users found")
	}
	for _, current := range targets {
		if current.UserID == "" {
			return fmt.Errorf("household user is missing a user ID")
		}
	}

	rows := make([]map[string]any, 0, len(targets))
	for _, current := range targets {
		away, err := cl.GetAwayMode(ctx, current.UserID)
		if err != nil {
			return fmt.Errorf("reading away for %s: %w", current.UserID, err)
		}
		rows = append(rows, map[string]any{
			"side":    current.SideLabel(),
			"name":    current.DisplayName(),
			"user_id": current.UserID,
			"away":    away,
		})
	}

	headers := []string{"side", "name", "user_id", "away"}
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
	return runAwayWithClient(context.Background(), cmd, cl, on)
}

func runAwayWithClient(ctx context.Context, cmd *cobra.Command, cl *client.Client, on bool) error {
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
		// The unfiltered device response can omit every user while away.
		// Household lookup explicitly requests the IDs needed for the writes.
		targets, err := cl.HouseholdUserTargets(ctx)
		if err != nil {
			return fmt.Errorf("fetching household users: %w", err)
		}
		if len(targets) == 0 {
			return fmt.Errorf("no household users found")
		}
		for _, current := range targets {
			if current.UserID == "" {
				return fmt.Errorf("household user is missing a user ID")
			}
		}
		for _, current := range targets {
			if err := cl.SetAwayMode(ctx, current.UserID, on); err != nil {
				return fmt.Errorf("setting away for %s: %w", current.UserID, err)
			}
		}
		scope = fmt.Sprintf("%d household members", len(targets))
		if len(targets) == 1 {
			scope = "1 household member"
		}
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
	awayCmd.AddCommand(awayOnCmd)
	awayCmd.AddCommand(awayOffCmd)
	awayCmd.AddCommand(awayStatusCmd)
}
