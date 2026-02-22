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
		tz := resolveTimezone(viper.GetString("timezone"))
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		day, err := cl.GetSleepDay(context.Background(), date, tz)
		if err != nil {
			return err
		}
		rows := []map[string]any{
			{
				"date":           day.Date,
				"score":          day.Score,
				"tnt":            day.Tnt,
				"resp_rate":      day.Respiratory,
				"heart_rate":     day.HeartRate,
				"duration":       day.Duration,
				"latency_asleep": day.LatencyAsleep,
				"latency_out":    day.LatencyOut,
				"hrv_score":      day.SleepQuality.HRV.Score,
			},
		}
		rows = output.FilterFields(rows, viper.GetStringSlice("fields"))
		return output.Print(output.Format(viper.GetString("output")), []string{"date", "score", "duration", "latency_asleep", "latency_out", "tnt", "resp_rate", "heart_rate", "hrv_score"}, rows)
	},
}

func init() {
	sleepCmd.PersistentFlags().String("date", "", "date YYYY-MM-DD (default today)")
	viper.BindPFlag("date", sleepCmd.PersistentFlags().Lookup("date"))
	sleepCmd.AddCommand(sleepDayCmd)
}
