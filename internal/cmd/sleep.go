package cmd

import (
	"context"
	"math"
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
		date, _ := cmd.Flags().GetString("date")
		if date == "" {
			date = time.Now().Format("2006-01-02")
		}
		tz := viper.GetString("timezone")
		if tz == "local" {
			tz = time.Local.String()
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		ctx := context.Background()
		side, _ := cmd.Flags().GetString("side")
		userID, err := cl.UserIDForSide(ctx, side)
		if err != nil {
			return err
		}
		day, err := cl.GetSleepDayForUser(ctx, userID, date, tz)
		if err != nil {
			return err
		}
		// Convert durations from seconds to hours/minutes for readability
		r1 := func(v float64) float64 { return math.Round(v*10) / 10 }
		durationHrs := r1(day.Duration / 3600)
		deepHrs := r1(day.DeepDuration / 3600)
		remHrs := r1(day.RemDuration / 3600)
		lightHrs := r1(day.LightDuration / 3600)
		awakeMin := r1((day.PresenceDuration - day.Duration) / 60)
		snoreMin := r1(day.SnoreDuration / 60)

		rows := []map[string]any{
			{
				"date":         day.Date,
				"score":        day.Score,
				"quality":      day.SleepQuality.Total,
				"duration_hrs": durationHrs,
				"deep_hrs":     deepHrs,
				"rem_hrs":      remHrs,
				"light_hrs":    lightHrs,
				"awake_min":    awakeMin,
				"disturbances": day.Tnt,
				"rhr":          day.SleepQuality.HeartRate.Current,
				"avg_rhr":      day.SleepQuality.HeartRate.Average,
				"lowest_hr":    day.LowestHeartRate(),
				"hrv":          day.SleepQuality.HRV.Current,
				"breath_rate":  day.SleepQuality.Respiratory.Current,
				"snore_min":    snoreMin,
				"sleep_start":  day.SleepStart,
				"sleep_end":    day.SleepEnd,
			},
		}
		rows = output.FilterFields(rows, viper.GetStringSlice("fields"))
		return output.Print(output.Format(viper.GetString("output")), []string{
			"date", "score", "quality", "duration_hrs",
			"deep_hrs", "rem_hrs", "light_hrs",
			"awake_min", "disturbances",
			"rhr", "avg_rhr", "lowest_hr",
			"hrv", "breath_rate", "snore_min",
			"sleep_start", "sleep_end",
		}, rows)
	},
}

func init() {
	sleepCmd.PersistentFlags().String("date", "", "date YYYY-MM-DD (default today)")
	sleepCmd.PersistentFlags().String("side", "", "bed side: left, right, partner, or me (default: me)")
	sleepCmd.AddCommand(sleepDayCmd)
}
