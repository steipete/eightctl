package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
)

var alarmCmd = &cobra.Command{
	Use:   "alarm",
	Short: "Manage alarms",
}

var alarmListCmd = &cobra.Command{
	Use:   "list",
	Short: "List alarms",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		alarms, err := cl.ListAlarms(context.Background())
		if err != nil {
			return err
		}
		rows := make([]map[string]any, 0, len(alarms))
		for _, a := range alarms {
			rows = append(rows, map[string]any{
				"id":        a.ID,
				"time":      a.Time,
				"enabled":   a.Enabled,
				"days":      a.DaysOfWeek,
				"vibration": a.Vibration,
				"sound":     a.Sound,
			})
		}
		rows = output.FilterFields(rows, viper.GetStringSlice("fields"))
		return output.Print(output.Format(viper.GetString("output")), []string{"id", "time", "enabled", "days", "vibration", "sound"}, rows)
	},
}

var alarmCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an alarm",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		timeStr := viper.GetString("time")
		if timeStr == "" {
			return fmt.Errorf("--time required")
		}
		days := viper.GetIntSlice("days")
		if len(days) == 0 {
			return fmt.Errorf("--days required (comma separated 0=Sun..6=Sat)")
		}
		sound := viper.GetString("sound")
		var soundPtr *string
		if sound != "" {
			soundPtr = &sound
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		alarm := client.Alarm{
			Enabled:    !viper.GetBool("disabled"),
			Time:       timeStr,
			DaysOfWeek: days,
			Vibration:  !viper.GetBool("no-vibration"),
			Sound:      soundPtr,
		}
		res, err := cl.CreateAlarm(context.Background(), alarm)
		if err != nil {
			return err
		}
		fmt.Printf("created alarm %s\n", res.ID)
		return nil
	},
}

var alarmCreateOneOffCmd = &cobra.Command{
	Use:   "create-one-off",
	Short: "Create a single-use alarm",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		timeStr, err := normalizeAlarmTime(viper.GetString("one-off-time"))
		if err != nil {
			return err
		}
		vibrationLevel := viper.GetInt("one-off-vibration-level")
		if vibrationLevel != 20 && vibrationLevel != 50 && vibrationLevel != 100 {
			return fmt.Errorf("--vibration-level must be 20, 50, or 100")
		}
		pattern, err := normalizeOneOffPattern(viper.GetString("one-off-pattern"))
		if err != nil {
			return err
		}
		thermalEnabled := oneOffThermalLevelProvided(cmd) && !viper.GetBool("one-off-no-thermal")
		thermalLevel := viper.GetInt("one-off-thermal-level")
		if thermalEnabled && (thermalLevel < -100 || thermalLevel > 100) {
			return fmt.Errorf("--thermal-level must be between -100 and 100")
		}
		smart := smartAlarmSettings(viper.GetBool("one-off-smart"))

		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		res, err := cl.CreateOneOffAlarm(context.Background(), client.OneOffAlarm{
			Enabled: true,
			Time:    timeStr,
			Vibration: client.AlarmVibration{
				Enabled:    !viper.GetBool("one-off-no-vibration"),
				PowerLevel: vibrationLevel,
				Pattern:    pattern,
			},
			Thermal: client.AlarmThermal{
				Enabled: thermalEnabled,
				Level:   thermalLevel,
			},
			Smart: smart,
		})
		if err != nil {
			return err
		}
		if smart != nil {
			if err := verifySmartAlarm(res); err != nil {
				return err
			}
			if res.ID == "" {
				return fmt.Errorf("Smart Alarm response did not include an ID for read-back")
			}
			persisted, err := cl.FindAlarmV2(context.Background(), res.ID)
			if err != nil {
				return fmt.Errorf("Smart Alarm read-back failed: %w", err)
			}
			if err := verifySmartAlarm(persisted); err != nil {
				return fmt.Errorf("Smart Alarm read-back failed: %w", err)
			}
		}
		if res.ID != "" {
			fmt.Printf("created one-off alarm %s for %s\n", res.ID, res.Time)
		} else {
			fmt.Printf("created one-off alarm for %s\n", res.Time)
		}
		return nil
	},
}

func verifySmartAlarm(alarm *client.OneOffAlarm) error {
	if alarm == nil || alarm.Smart == nil || !alarm.Smart.LightSleepEnabled {
		return fmt.Errorf("Eight Sleep did not confirm Smart Alarm light-sleep support")
	}
	if alarm.Smart.SleepCapEnabled || alarm.Smart.SleepCapMinutes != 480 {
		return fmt.Errorf("Eight Sleep did not confirm the Smart Alarm sleep cap settings")
	}
	return nil
}

func smartAlarmSettings(enabled bool) *client.AlarmSmart {
	if !enabled {
		return nil
	}
	return &client.AlarmSmart{
		LightSleepEnabled: true,
		SleepCapEnabled:   false,
		SleepCapMinutes:   480,
	}
}

func normalizeOneOffPattern(value string) (string, error) {
	switch strings.ToUpper(value) {
	case "RISE":
		return "RISE", nil
	case "INTENSE":
		return "intense", nil
	default:
		return "", fmt.Errorf("--pattern must be RISE or INTENSE")
	}
}

func oneOffThermalLevelProvided(cmd *cobra.Command) bool {
	return cmd.Flags().Changed("thermal-level") || viper.IsSet("one-off-thermal-level")
}

func normalizeAlarmTime(value string) (string, error) {
	for _, layout := range []string{"15:04", "15:04:05"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.Format("15:04:05"), nil
		}
	}
	return "", fmt.Errorf("--time must be HH:MM or HH:MM:SS")
}

var alarmUpdateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update an alarm",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		patch := map[string]any{}
		if f := viper.GetString("time"); f != "" {
			patch["time"] = f
		}
		if days := viper.GetIntSlice("days"); len(days) > 0 {
			patch["daysOfWeek"] = days
		}
		if cmd.Flags().Changed("enabled") {
			patch["enabled"] = viper.GetBool("enabled")
		}
		if cmd.Flags().Changed("no-vibration") {
			patch["vibration"] = !viper.GetBool("no-vibration")
		}
		if sound := viper.GetString("sound"); sound != "" {
			patch["sound"] = sound
		}
		if len(patch) == 0 {
			return fmt.Errorf("no fields to update")
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		if _, err := cl.UpdateAlarm(context.Background(), args[0], patch); err != nil {
			return err
		}
		fmt.Println("updated")
		return nil
	},
}

var alarmDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete an alarm",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		if err := cl.DeleteAlarm(context.Background(), args[0]); err != nil {
			return err
		}
		fmt.Println("deleted")
		return nil
	},
}

func init() {
	alarmCreateCmd.Flags().String("time", "", "HH:MM time")
	alarmCreateCmd.Flags().IntSlice("days", nil, "Comma-separated days 0=Sun..6=Sat")
	alarmCreateCmd.Flags().Bool("disabled", false, "Create disabled")
	alarmCreateCmd.Flags().Bool("no-vibration", false, "Disable vibration")
	alarmCreateCmd.Flags().String("sound", "", "Sound id")
	viper.BindPFlag("time", alarmCreateCmd.Flags().Lookup("time"))
	viper.BindPFlag("days", alarmCreateCmd.Flags().Lookup("days"))
	viper.BindPFlag("disabled", alarmCreateCmd.Flags().Lookup("disabled"))
	viper.BindPFlag("no-vibration", alarmCreateCmd.Flags().Lookup("no-vibration"))
	viper.BindPFlag("sound", alarmCreateCmd.Flags().Lookup("sound"))

	alarmCreateOneOffCmd.Flags().String("time", "", "HH:MM or HH:MM:SS time")
	alarmCreateOneOffCmd.Flags().Bool("no-vibration", false, "Disable vibration")
	alarmCreateOneOffCmd.Flags().Int("vibration-level", 50, "Vibration level: 20, 50, or 100")
	alarmCreateOneOffCmd.Flags().String("pattern", "RISE", "Vibration pattern: RISE or INTENSE")
	alarmCreateOneOffCmd.Flags().Int("thermal-level", 0, "Thermal wake level (-100..100); enables thermal wake when supplied")
	alarmCreateOneOffCmd.Flags().Bool("no-thermal", false, "Disable thermal wake")
	alarmCreateOneOffCmd.Flags().Bool("smart", false, "Enable Smart Alarm/light-sleep wake window")
	viper.BindPFlag("one-off-time", alarmCreateOneOffCmd.Flags().Lookup("time"))
	viper.BindPFlag("one-off-no-vibration", alarmCreateOneOffCmd.Flags().Lookup("no-vibration"))
	viper.BindPFlag("one-off-vibration-level", alarmCreateOneOffCmd.Flags().Lookup("vibration-level"))
	viper.BindPFlag("one-off-pattern", alarmCreateOneOffCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("one-off-thermal-level", alarmCreateOneOffCmd.Flags().Lookup("thermal-level"))
	viper.BindPFlag("one-off-no-thermal", alarmCreateOneOffCmd.Flags().Lookup("no-thermal"))
	viper.BindPFlag("one-off-smart", alarmCreateOneOffCmd.Flags().Lookup("smart"))

	alarmUpdateCmd.Flags().String("time", "", "HH:MM time")
	alarmUpdateCmd.Flags().IntSlice("days", nil, "Comma-separated days 0=Sun..6=Sat")
	alarmUpdateCmd.Flags().Bool("enabled", true, "Set enabled true/false")
	alarmUpdateCmd.Flags().Bool("no-vibration", false, "Disable vibration")
	alarmUpdateCmd.Flags().String("sound", "", "Sound id")
	viper.BindPFlag("time", alarmUpdateCmd.Flags().Lookup("time"))
	viper.BindPFlag("days", alarmUpdateCmd.Flags().Lookup("days"))
	viper.BindPFlag("enabled", alarmUpdateCmd.Flags().Lookup("enabled"))
	viper.BindPFlag("no-vibration", alarmUpdateCmd.Flags().Lookup("no-vibration"))
	viper.BindPFlag("sound", alarmUpdateCmd.Flags().Lookup("sound"))

	// add subcommands
	alarmCmd.AddCommand(alarmListCmd, alarmCreateCmd, alarmCreateOneOffCmd, alarmUpdateCmd, alarmDeleteCmd, alarmSnoozeCmd, alarmDismissCmd, alarmDismissAllCmd, alarmVibeCmd)
}

// snooze
var alarmSnoozeCmd = &cobra.Command{Use: "snooze <id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Alarms().Snooze(context.Background(), args[0])
}}

var alarmDismissCmd = &cobra.Command{Use: "dismiss <id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Alarms().Dismiss(context.Background(), args[0])
}}

var alarmDismissAllCmd = &cobra.Command{Use: "dismiss-all", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Alarms().DismissAll(context.Background())
}}

var alarmVibeCmd = &cobra.Command{Use: "vibration-test", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Alarms().VibrationTest(context.Background())
}}

// parseDays convenience to support comma inputs (unused, kept for future).
func parseDays(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	res := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var v int
		if _, err := fmt.Sscanf(p, "%d", &v); err != nil {
			return nil, err
		}
		res = append(res, v)
	}
	return res, nil
}
