package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var householdCmd = &cobra.Command{Use: "household", Short: "Household info"}

func householdSimple(name string, fn func(*client.Client, context.Context) (any, error)) *cobra.Command {
	return &cobra.Command{Use: name, RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		res, err := fn(cl, context.Background())
		if err != nil {
			return err
		}
		return printRows([]string{name}, []map[string]any{{name: res}})
	}}
}

func init() {
	householdCmd.AddCommand(
		householdSimple("summary", func(cl *client.Client, ctx context.Context) (any, error) { return cl.Household().Summary(ctx) }),
		householdSimple("schedule", func(cl *client.Client, ctx context.Context) (any, error) { return cl.Household().Schedule(ctx) }),
		householdSimple("current-set", func(cl *client.Client, ctx context.Context) (any, error) { return cl.Household().CurrentSet(ctx) }),
		householdSimple("invitations", func(cl *client.Client, ctx context.Context) (any, error) { return cl.Household().Invitations(ctx) }),
		householdSimple("devices", func(cl *client.Client, ctx context.Context) (any, error) { return cl.Household().Devices(ctx) }),
		householdSimple("users", func(cl *client.Client, ctx context.Context) (any, error) { return cl.Household().Users(ctx) }),
		householdSimple("guests", func(cl *client.Client, ctx context.Context) (any, error) { return cl.Household().Guests(ctx) }),
	)
}
