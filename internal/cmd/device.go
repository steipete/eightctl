package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var deviceCmd = &cobra.Command{Use: "device", Short: "Device info and priming"}

func deviceSimple(name string, fn func(ctx context.Context) (any, error)) *cobra.Command {
	return &cobra.Command{Use: name, RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		res, err := fn(cmd.Context())
		if err != nil {
			return err
		}
		return printRows([]string{name}, []map[string]any{{name: res}})
	}}
}

func init() {
	deviceCmd.AddCommand(
		deviceSimple("info", func(ctx context.Context) (any, error) {
			cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
			return cl.Device().Info(ctx)
		}),
		deviceSimple("peripherals", func(ctx context.Context) (any, error) {
			cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
			return cl.Device().Peripherals(ctx)
		}),
		deviceSimple("owner", func(ctx context.Context) (any, error) {
			cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
			return cl.Device().Owner(ctx)
		}),
		deviceSimple("warranty", func(ctx context.Context) (any, error) {
			cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
			return cl.Device().Warranty(ctx)
		}),
		deviceSimple("online", func(ctx context.Context) (any, error) {
			cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
			return cl.Device().Online(ctx)
		}),
		deviceSimple("priming-tasks", func(ctx context.Context) (any, error) {
			cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
			return cl.Device().PrimingTasks(ctx)
		}),
		deviceSimple("priming-schedule", func(ctx context.Context) (any, error) {
			cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
			return cl.Device().PrimingSchedule(ctx)
		}),
	)
}
