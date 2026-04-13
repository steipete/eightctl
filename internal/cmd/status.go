package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show device status",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		allSides, err := cmd.Flags().GetBool("all-sides")
		if err != nil {
			return err
		}
		target, err := resolveSelectedTarget(context.Background(), cmd, cl)
		if err != nil {
			return err
		}
		if allSides && target != nil {
			return fmt.Errorf("use --all-sides by itself, not with --side or --target-user-id")
		}
		rows := []map[string]any{}
		headers := []string{"mode", "level"}
		if allSides {
			targets, err := cl.HouseholdUserTargets(context.Background())
			if err != nil {
				return err
			}
			rows, err = householdStatusRows(context.Background(), cl, targets)
			if err != nil {
				return err
			}
			headers = householdStatusHeaders()
		} else {
			rows, headers, err = defaultStatusRows(context.Background(), cl, target)
			if err != nil {
				return err
			}
		}
		fields := viper.GetStringSlice("fields")
		rows = output.FilterFields(rows, fields)
		if len(fields) > 0 {
			headers = fields
		}
		return output.Print(output.Format(viper.GetString("output")), headers, rows)
	},
}

func init() {
	addTargetingFlags(statusCmd, true)
	statusCmd.Flags().Bool("all-sides", false, "show status for all discovered household sides")
}

func defaultStatusRows(ctx context.Context, cl *client.Client, target *client.HouseholdUserTarget) ([]map[string]any, []string, error) {
	if target != nil {
		st, err := cl.GetStatusForUser(ctx, target.UserID)
		if err != nil {
			return nil, nil, err
		}
		return []map[string]any{{
			"side":    target.SideLabel(),
			"name":    target.DisplayName(),
			"user_id": target.UserID,
			"mode":    st.CurrentState.Type,
			"level":   st.CurrentLevel,
		}}, householdStatusHeaders(), nil
	}

	targets, err := cl.HouseholdUserTargets(ctx)
	if err == nil && len(targets) > 0 {
		rows, err := householdStatusRows(ctx, cl, targets)
		if err != nil {
			return nil, nil, err
		}
		return rows, householdStatusHeaders(), nil
	}

	st, err := cl.GetStatusForUser(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	return []map[string]any{{"mode": st.CurrentState.Type, "level": st.CurrentLevel}}, []string{"mode", "level"}, nil
}

func householdStatusRows(ctx context.Context, cl *client.Client, targets []client.HouseholdUserTarget) ([]map[string]any, error) {
	rows := make([]map[string]any, 0, len(targets))
	for _, current := range targets {
		st, err := cl.GetStatusForUser(ctx, current.UserID)
		if err != nil {
			return nil, err
		}
		rows = append(rows, map[string]any{
			"side":    current.SideLabel(),
			"name":    current.DisplayName(),
			"user_id": current.UserID,
			"mode":    st.CurrentState.Type,
			"level":   st.CurrentLevel,
		})
	}
	return rows, nil
}

func householdStatusHeaders() []string {
	return []string{"side", "name", "user_id", "mode", "level"}
}
