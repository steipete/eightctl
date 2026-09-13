package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var tempModeCmd = &cobra.Command{
	Use:   "tempmode",
	Short: "Temperature modes (nap, hot-flash, temp events)",
}

var (
	tempNapCmd   = &cobra.Command{Use: "nap", Short: "Nap mode controls"}
	tempNapOnCmd = &cobra.Command{Use: "on", RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		return cl.TempModes().NapActivate(context.Background())
	}}
)

var tempNapOffCmd = &cobra.Command{Use: "off", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.TempModes().NapDeactivate(context.Background())
}}

var tempNapExtendCmd = &cobra.Command{Use: "extend", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.TempModes().NapExtend(context.Background())
}}

var tempNapStatusCmd = &cobra.Command{Use: "status", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	var out map[string]any
	if err := cl.TempModes().NapStatus(context.Background(), &out); err != nil {
		return err
	}
	return printRows(mapKeys(out), []map[string]any{out})
}}

var (
	tempHotCmd   = &cobra.Command{Use: "hotflash", Short: "Hot-flash mode controls"}
	tempHotOnCmd = &cobra.Command{Use: "on", RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		return cl.TempModes().HotFlashActivate(context.Background())
	}}
)

var tempHotOffCmd = &cobra.Command{Use: "off", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.TempModes().HotFlashDeactivate(context.Background())
}}

var tempHotStatusCmd = &cobra.Command{Use: "status", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	var out map[string]any
	if err := cl.TempModes().HotFlashStatus(context.Background(), &out); err != nil {
		return err
	}
	return printRows(mapKeys(out), []map[string]any{out})
}}

var tempEventsCmd = &cobra.Command{Use: "events", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	from := viper.GetString("from")
	to := viper.GetString("to")
	var out any
	if err := cl.TempModes().TempEvents(context.Background(), from, to, &out); err != nil {
		return err
	}
	return printRows([]string{"events"}, []map[string]any{{"events": out}})
}}

func init() {
	tempNapCmd.AddCommand(tempNapOnCmd, tempNapOffCmd, tempNapExtendCmd, tempNapStatusCmd)
	tempHotCmd.AddCommand(tempHotOnCmd, tempHotOffCmd, tempHotStatusCmd)
	tempEventsCmd.Flags().String("from", "", "from date (YYYY-MM-DD)")
	tempEventsCmd.Flags().String("to", "", "to date (YYYY-MM-DD)")

	tempModeCmd.AddCommand(tempNapCmd, tempHotCmd, tempEventsCmd)
}
