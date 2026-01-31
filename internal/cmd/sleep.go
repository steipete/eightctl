package cmd

import (
	"context"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
)

var sleepCmd = &cobra.Command{
	Use:   "sleep",
	Short: "Sleep analytics commands",
}

var sleepDayCmd = &cobra.Command{
	Use:   "day",
	Short: "Fetch sleep metrics for a date (YYYY-MM-DD)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		date := viper.GetString("date")
		if date == "" {
			date = time.Now().Format("2006-01-02")
		}
		tz := viper.GetString("timezone")
		if tz == "local" {
			tz = time.Local.String()
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		day, err := cl.GetSleepDay(context.Background(), date, tz)
		if err != nil {
			return err
		}
		// Convert durations from seconds to hours for readability
		durationHrs := day.Duration / 3600
		deepHrs := day.DeepDuration / 3600
		remHrs := day.RemDuration / 3600
		lightHrs := day.LightDuration / 3600

		rows := []map[string]any{
			{
				"date":         day.Date,
				"score":        day.Score,
				"duration_hrs": float64(int(durationHrs*10)) / 10,
				"deep_hrs":     float64(int(deepHrs*10)) / 10,
				"rem_hrs":      float64(int(remHrs*10)) / 10,
				"light_hrs":    float64(int(lightHrs*10)) / 10,
				"sleep_start":  day.SleepStart,
				"sleep_end":    day.SleepEnd,
				"tnt":          day.Tnt,
				"rhr":          day.SleepQuality.HeartRate.Current,
				"hrv":          day.SleepQuality.HRV.Current,
				"resp_rate":    day.SleepQuality.Respiratory.Current,
			},
		}
		rows = output.FilterFields(rows, viper.GetStringSlice("fields"))
		return output.Print(output.Format(viper.GetString("output")), []string{"date", "score", "duration_hrs", "deep_hrs", "rem_hrs", "light_hrs", "rhr", "hrv", "resp_rate", "tnt", "sleep_start", "sleep_end"}, rows)
	},
}

func init() {
	sleepCmd.PersistentFlags().String("date", "", "date YYYY-MM-DD (default today)")
	viper.BindPFlag("date", sleepCmd.PersistentFlags().Lookup("date"))
	sleepCmd.AddCommand(sleepDayCmd)
}
