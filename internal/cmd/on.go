package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var onCmd = &cobra.Command{
	Use:   "on",
	Short: "Turn pod on",
	RunE:  func(cmd *cobra.Command, args []string) error { return runPower(cmd, true) },
}

func runPower(cmd *cobra.Command, on bool) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	setPower := cl.TurnOffForUser
	state := "off"
	if on {
		setPower = cl.TurnOnForUser
		state = "on"
	}
	targets, targeted, err := resolveCommandTargets(context.Background(), cmd, cl)
	if err != nil {
		return err
	}
	if targeted {
		for _, target := range targets {
			if err := setPower(context.Background(), target.UserID); err != nil {
				return err
			}
		}
		fmt.Printf("pod turned %s%s\n", state, targetListSuffix(targets))
		return nil
	}

	if err := setPower(context.Background(), ""); err != nil {
		return err
	}
	fmt.Printf("pod turned %s\n", state)
	return nil
}

func init() {
	addTargetingFlags(onCmd, true)
}
