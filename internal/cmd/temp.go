package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/daemon"
)

var tempCmd = &cobra.Command{
	Use:                "temp <value>",
	Short:              "Set pod temperature (e.g., 68F, 20C, or heating level -100..100)",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		tempValue, targetUserID, side, help, err := parseTempCommandArgs(args)
		if err != nil {
			return err
		}
		if help {
			return cmd.Help()
		}
		lvl, err := daemon.ParseTemp(tempValue)
		if err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		targets, targeted, err := resolveCommandTargetValues(context.Background(), cl, targetUserID, side)
		if err != nil {
			return err
		}
		if targeted {
			for _, target := range targets {
				if err := cl.SetTemperatureForUser(context.Background(), target.UserID, lvl); err != nil {
					return err
				}
			}
			fmt.Printf("temperature set (level %d)%s\n", lvl, targetListSuffix(targets))
			return nil
		}

		if err := cl.SetTemperatureForUser(context.Background(), "", lvl); err != nil {
			return err
		}
		fmt.Printf("temperature set (level %d)\n", lvl)
		return nil
	},
}

func init() {
	addTargetingFlags(tempCmd, true)
}

func parseTempCommandArgs(args []string) (tempValue string, targetUserID string, side string, help bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			return "", "", "", true, nil
		case arg == "--side":
			i++
			if i >= len(args) {
				return "", "", "", false, fmt.Errorf("flag needs an argument: --side")
			}
			side = args[i]
		case strings.HasPrefix(arg, "--side="):
			side = strings.TrimPrefix(arg, "--side=")
		case arg == "--target-user-id":
			i++
			if i >= len(args) {
				return "", "", "", false, fmt.Errorf("flag needs an argument: --target-user-id")
			}
			targetUserID = args[i]
		case strings.HasPrefix(arg, "--target-user-id="):
			targetUserID = strings.TrimPrefix(arg, "--target-user-id=")
		case arg == "--":
			if i+1 >= len(args) {
				return "", "", "", false, fmt.Errorf("requires exactly 1 temperature value")
			}
			if tempValue != "" || len(args[i+1:]) != 1 {
				return "", "", "", false, fmt.Errorf("requires exactly 1 temperature value")
			}
			tempValue = args[i+1]
			i = len(args)
		case strings.HasPrefix(arg, "-") && !isNegativeTempCandidate(arg):
			return "", "", "", false, fmt.Errorf("unknown flag: %s", arg)
		default:
			if tempValue != "" {
				return "", "", "", false, fmt.Errorf("requires exactly 1 temperature value")
			}
			tempValue = arg
		}
	}

	if tempValue == "" {
		return "", "", "", false, fmt.Errorf("requires exactly 1 temperature value")
	}
	return tempValue, targetUserID, side, false, nil
}

func isNegativeTempCandidate(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	b := arg[1]
	return (b >= '0' && b <= '9') || b == '.'
}
