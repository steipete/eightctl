package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/steipete/eightctl/internal/client"
)

func addTargetingFlags(cmd *cobra.Command, includeTargetUser bool) {
	cmd.Flags().String("side", "", "target household side: left|right|solo")
	if includeTargetUser {
		cmd.Flags().String("target-user-id", "", "set or query a specific household user ID")
	}
}

func resolveSelectedTarget(ctx context.Context, cmd *cobra.Command, cl *client.Client) (*client.HouseholdUserTarget, error) {
	targetUserID, err := cmd.Flags().GetString("target-user-id")
	if err != nil {
		return nil, err
	}
	side, err := cmd.Flags().GetString("side")
	if err != nil {
		return nil, err
	}
	return resolveSelectedTargetValues(ctx, cl, targetUserID, side)
}

func resolveCommandTargets(ctx context.Context, cmd *cobra.Command, cl *client.Client) ([]client.HouseholdUserTarget, bool, error) {
	targetUserID, err := cmd.Flags().GetString("target-user-id")
	if err != nil {
		return nil, false, err
	}
	side, err := cmd.Flags().GetString("side")
	if err != nil {
		return nil, false, err
	}
	return resolveCommandTargetValues(ctx, cl, targetUserID, side)
}

func resolveSelectedTargetValues(ctx context.Context, cl *client.Client, targetUserID string, side string) (*client.HouseholdUserTarget, error) {
	if targetUserID != "" && side != "" {
		return nil, fmt.Errorf("use either --target-user-id or --side, not both")
	}
	if side != "" {
		targets, err := cl.HouseholdUserTargets(ctx)
		if err != nil {
			return nil, err
		}
		return client.ResolveHouseholdSide(targets, side)
	}
	if targetUserID == "" {
		return nil, nil
	}

	targets, err := cl.HouseholdUserTargets(ctx)
	if err != nil {
		return &client.HouseholdUserTarget{UserID: targetUserID}, nil
	}
	for _, target := range targets {
		if target.UserID == targetUserID {
			return &target, nil
		}
	}
	return &client.HouseholdUserTarget{UserID: targetUserID}, nil
}

func resolveCommandTargetValues(ctx context.Context, cl *client.Client, targetUserID string, side string) ([]client.HouseholdUserTarget, bool, error) {
	if targetUserID != "" || side != "" {
		target, err := resolveSelectedTargetValues(ctx, cl, targetUserID, side)
		if err != nil {
			return nil, false, err
		}
		if target == nil {
			return nil, false, nil
		}
		return []client.HouseholdUserTarget{*target}, true, nil
	}

	targets, err := cl.HouseholdUserTargets(ctx)
	if err != nil || len(targets) == 0 {
		return nil, false, nil
	}
	return targets, true, nil
}

func targetSuffix(target *client.HouseholdUserTarget) string {
	if target == nil {
		return ""
	}
	if side := strings.TrimSpace(target.Side); side != "" {
		return " for side " + side
	}
	if target.UserID != "" {
		return " for user " + target.UserID
	}
	return ""
}

func targetListSuffix(targets []client.HouseholdUserTarget) string {
	if len(targets) == 0 {
		return ""
	}
	if len(targets) == 1 {
		target := targets[0]
		return targetSuffix(&target)
	}

	sides := []string{}
	for _, target := range targets {
		side := strings.TrimSpace(target.Side)
		if side == "" {
			return " for all discovered users"
		}
		sides = append(sides, side)
	}
	return " for sides " + strings.Join(sides, ", ")
}
