package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
)

var autopilotCmd = &cobra.Command{Use: "autopilot", Short: "Autopilot settings"}

var (
	autopilotDetailsCmd = simpleAutopilot("details", func(cl *client.Client, ctx context.Context) (any, error) { return cl.Autopilot().Details(ctx) })
	autopilotHistoryCmd = simpleAutopilot("history", func(cl *client.Client, ctx context.Context) (any, error) { return cl.Autopilot().History(ctx) })
	autopilotRecapCmd   = simpleAutopilot("recap", func(cl *client.Client, ctx context.Context) (any, error) { return cl.Autopilot().Recap(ctx) })
)

var autopilotLevelCmd = &cobra.Command{Use: "level-suggestions", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	enabled := viper.GetBool("enabled")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Autopilot().SetLevelSuggestions(context.Background(), enabled)
}}

var autopilotSnoreCmd = &cobra.Command{Use: "snore-mitigation", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	enabled := viper.GetBool("enabled")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Autopilot().SetSnoreMitigation(context.Background(), enabled)
}}

func simpleAutopilot(name string, fn func(*client.Client, context.Context) (any, error)) *cobra.Command {
	return &cobra.Command{Use: name, RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		res, err := fn(cl, context.Background())
		if err != nil {
			return err
		}
		return output.Print(output.Format(viper.GetString("output")), []string{name}, []map[string]any{{name: res}})
	}}
}

func init() {
	autopilotLevelCmd.Flags().Bool("enabled", true, "enable or disable")
	autopilotSnoreCmd.Flags().Bool("enabled", true, "enable or disable")

	autopilotCmd.AddCommand(autopilotDetailsCmd, autopilotHistoryCmd, autopilotRecapCmd, autopilotLevelCmd, autopilotSnoreCmd)
}
