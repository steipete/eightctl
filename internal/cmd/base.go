package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var baseCmd = &cobra.Command{Use: "base", Short: "Adjustable base controls"}

var baseInfoCmd = &cobra.Command{Use: "info", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Base().Info(context.Background())
	if err != nil {
		return err
	}
	return printRows([]string{"info"}, []map[string]any{{"info": res}})
}}

var baseAngleCmd = &cobra.Command{Use: "angle", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	head := viper.GetInt("head")
	foot := viper.GetInt("foot")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Base().SetAngle(context.Background(), head, foot)
}}

var basePresetsCmd = &cobra.Command{Use: "presets", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Base().Presets(context.Background())
	if err != nil {
		return err
	}
	return printRows([]string{"presets"}, []map[string]any{{"presets": res}})
}}

var basePresetRunCmd = &cobra.Command{Use: "preset-run", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	name := viper.GetString("name")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Base().RunPreset(context.Background(), name)
}}

var baseTestCmd = &cobra.Command{Use: "test", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Base().VibrationTest(context.Background())
}}

func init() {
	baseAngleCmd.Flags().Int("head", 0, "head angle")
	baseAngleCmd.Flags().Int("foot", 0, "foot angle")
	basePresetRunCmd.Flags().String("name", "", "preset name")

	baseCmd.AddCommand(baseInfoCmd, baseAngleCmd, basePresetsCmd, basePresetRunCmd, baseTestCmd)
}
