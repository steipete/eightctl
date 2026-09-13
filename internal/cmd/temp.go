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
		if help, _ := cmd.Flags().GetBool("help"); help {
			return cmd.Help()
		}
		lvl, err := daemon.ParseTemp(cmd.Flags().Arg(0))
		if err != nil {
			return err
		}
		if err := requireAuthFields(); err != nil {
			return err
		}
		targetUserID, _ := cmd.Flags().GetString("target-user-id")
		side, _ := cmd.Flags().GetString("side")
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

// Move positional temperatures after -- while preserving option values, so pflag
// can parse inherited flags without mistaking a negative temperature for a flag.
func parseTemperatureFlags(cmd *cobra.Command, args []string) error {
	cmd.Flags().AddFlagSet(cmd.InheritedFlags())
	cmd.InitDefaultHelpFlag()
	var options, values []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			values = append(values, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && !isNegativeTempCandidate(arg) {
			options = append(options, arg)
			if name, _, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "="); strings.HasPrefix(arg, "--") && !hasValue {
				flag := cmd.Flags().Lookup(name)
				if flag != nil && flag.NoOptDefVal == "" && i+1 < len(args) {
					i++
					options = append(options, args[i])
				}
			}
		} else {
			values = append(values, arg)
		}
	}
	options = append(options, "--")
	if err := cmd.Flags().Parse(append(options, values...)); err != nil {
		return err
	}
	if help, _ := cmd.Flags().GetBool("help"); help {
		return nil
	}
	if cmd.Flags().NArg() != 1 {
		return fmt.Errorf("requires exactly 1 temperature value")
	}
	return nil
}

func isNegativeTempCandidate(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	b := arg[1]
	return (b >= '0' && b <= '9') || b == '.'
}
