package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
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
		return printRows([]string{"id", "time", "enabled", "days", "vibration", "sound"}, rows)
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
	Short: "Create a single-use alarm (experimental)",
	Long: "Create a single-use alarm through an undocumented provider API. " +
		"Compatibility and device behavior still require controlled-account verification. " +
		"Smart Alarm does not enable thermal wake; supply --thermal-level to opt in.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		alarm, err := oneOffAlarmFromFlags(cmd)
		if err != nil {
			return err
		}
		smart := alarm.Smart

		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		afterAttempt, err := cmd.Flags().GetString("after-attempt")
		if err != nil {
			return err
		}
		var res *client.OneOffAlarm
		if afterAttempt == "" {
			res, err = cl.CreateOneOffAlarm(context.Background(), alarm)
		} else {
			res, err = cl.CreateNextOneOffAlarm(context.Background(), alarm, afterAttempt)
		}
		if err != nil {
			return err
		}
		if smart != nil {
			if res.ID == "" {
				return fmt.Errorf("smart alarm creation may have succeeded, but the response did not include an ID for read-back")
			}
			if err := verifyPersistedSmartAlarm(func() (*client.OneOffAlarm, error) {
				return cl.FindAlarmV2(context.Background(), res.ID)
			}, 3, 250*time.Millisecond); err != nil {
				return fmt.Errorf("smart alarm creation may have succeeded for %s (attempt %s), but read-back failed: %w", res.ID, res.CreationAttempt, err)
			}
		}
		if res.ID != "" {
			fmt.Printf("created one-off alarm %s for %s (attempt %s)\n", res.ID, res.Time, res.CreationAttempt)
		} else {
			fmt.Printf("created one-off alarm for %s\n", res.Time)
		}
		return nil
	},
}

func oneOffAlarmFromFlags(cmd *cobra.Command) (client.OneOffAlarm, error) {
	timeStr, err := normalizeAlarmTime(viper.GetString("one-off-time"))
	if err != nil {
		return client.OneOffAlarm{}, err
	}
	vibrationLevel := viper.GetInt("one-off-vibration-level")
	if vibrationLevel != 20 && vibrationLevel != 50 && vibrationLevel != 100 {
		return client.OneOffAlarm{}, fmt.Errorf("--vibration-level must be 20, 50, or 100")
	}
	pattern, err := normalizeOneOffPattern(viper.GetString("one-off-pattern"))
	if err != nil {
		return client.OneOffAlarm{}, err
	}
	smartEnabled := viper.GetBool("one-off-smart")
	thermalProvided := oneOffThermalLevelProvided(cmd)
	thermalEnabled := thermalProvided && !viper.GetBool("one-off-no-thermal")
	thermalLevel := 0
	if thermalProvided {
		thermalLevel, err = strconv.Atoi(fmt.Sprint(viper.Get("one-off-thermal-level")))
		if err != nil {
			return client.OneOffAlarm{}, fmt.Errorf("--thermal-level must be an integer between -100 and 100")
		}
	}
	if err := validateOneOffThermalLevel(thermalProvided, thermalLevel); err != nil {
		return client.OneOffAlarm{}, err
	}
	return client.OneOffAlarm{
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
		Smart: smartAlarmSettings(smartEnabled),
	}, nil
}

func verifySmartAlarm(alarm *client.OneOffAlarm) error {
	if alarm == nil || alarm.Smart == nil || !alarm.Smart.LightSleepEnabled {
		return fmt.Errorf("provider did not confirm Smart Alarm light-sleep support")
	}
	if alarm.Smart.SleepCapEnabled || alarm.Smart.SleepCapMinutes != 480 {
		return fmt.Errorf("provider did not confirm the Smart Alarm sleep cap settings")
	}
	return nil
}

func verifyPersistedSmartAlarm(find func() (*client.OneOffAlarm, error), attempts int, delay time.Duration) error {
	if attempts < 1 {
		return fmt.Errorf("smart alarm read-back requires at least one attempt")
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		alarm, err := find()
		if err == nil {
			if err := verifySmartAlarm(alarm); err == nil {
				return nil
			} else {
				lastErr = err
			}
		} else {
			lastErr = err
		}
		if attempt+1 < attempts {
			time.Sleep(delay)
		}
	}
	return lastErr
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

func validateOneOffThermalLevel(provided bool, level int) error {
	if provided && (level < -100 || level > 100) {
		return fmt.Errorf("--thermal-level must be between -100 and 100")
	}
	return nil
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

	alarmCreateOneOffCmd.Flags().String("time", "", "HH:MM or HH:MM:SS time")
	alarmCreateOneOffCmd.Flags().Bool("no-vibration", false, "Disable vibration")
	alarmCreateOneOffCmd.Flags().Int("vibration-level", 50, "Vibration level: 20, 50, or 100")
	alarmCreateOneOffCmd.Flags().String("pattern", "RISE", "Vibration pattern: RISE or INTENSE")
	alarmCreateOneOffCmd.Flags().Int("thermal-level", 0, "Thermal wake level (-100..100); enables thermal wake when supplied")
	alarmCreateOneOffCmd.Flags().Bool("no-thermal", false, "Disable thermal wake")
	alarmCreateOneOffCmd.Flags().String("after-attempt", "", "Explicitly create another alarm after the latest confirmed attempt token")
	alarmCreateOneOffCmd.Flags().Bool("smart", false, "Enable Smart Alarm/light-sleep wake window; thermal wake remains opt-in")
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

	// add subcommands
	alarmCmd.AddCommand(alarmListCmd, alarmCreateCmd, alarmCreateOneOffCmd, alarmUpdateCmd, alarmDeleteCmd, alarmSnoozeCmd, alarmDismissCmd, alarmDismissAllCmd, alarmVibeCmd)
}

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
