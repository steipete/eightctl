package cmd

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
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
	return output.Print(output.Format(viper.GetString("output")), []string{"info"}, []map[string]any{{"info": res}})
}}

var baseAngleCmd = &cobra.Command{
	Use:   "angle [head] [foot]",
	Short: "Set head and foot angles (positional: angle 20 10, or flags: --head 20 --foot 10)",
	Args:  cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		head := viper.GetInt("head")
		foot := viper.GetInt("foot")
		// Positional args override flags if provided.
		if len(args) >= 1 {
			v, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid head angle %q: %w", args[0], err)
			}
			head = v
		}
		if len(args) >= 2 {
			v, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid foot angle %q: %w", args[1], err)
			}
			foot = v
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		return cl.Base().SetAngle(context.Background(), head, foot)
	},
}

var basePresetsCmd = &cobra.Command{Use: "presets", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Base().Presets(context.Background())
	if err != nil {
		return err
	}
	return output.Print(output.Format(viper.GetString("output")), []string{"presets"}, []map[string]any{{"presets": res}})
}}

var basePresetRunCmd = &cobra.Command{
	Use:   "preset-run [name]",
	Short: "Run a preset by name (positional: preset-run relaxing, or flag: --name relaxing)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		name := viper.GetString("name")
		// Positional arg overrides flag if provided.
		if len(args) >= 1 {
			name = args[0]
		}
		if name == "" {
			return fmt.Errorf("preset name required (positional arg or --name flag)")
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		return cl.Base().RunPreset(context.Background(), name)
	},
}

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
	viper.BindPFlag("head", baseAngleCmd.Flags().Lookup("head"))
	viper.BindPFlag("foot", baseAngleCmd.Flags().Lookup("foot"))
	basePresetRunCmd.Flags().String("name", "", "preset name")
	viper.BindPFlag("name", basePresetRunCmd.Flags().Lookup("name"))

	baseCmd.AddCommand(baseInfoCmd, baseAngleCmd, basePresetsCmd, basePresetRunCmd, baseTestCmd)
}
