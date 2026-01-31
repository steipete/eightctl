package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
)

var sleepRangeCmd = &cobra.Command{
	Use:   "range",
	Short: "Fetch sleep metrics for a date range",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		from, _ := cmd.Flags().GetString("from")
		to, _ := cmd.Flags().GetString("to")
		if from == "" || to == "" {
			return fmt.Errorf("--from and --to are required")
		}
		layout := "2006-01-02"
		start, err := time.Parse(layout, from)
		if err != nil {
			return err
		}
		end, err := time.Parse(layout, to)
		if err != nil {
			return err
		}
		if end.Before(start) {
			return fmt.Errorf("to must be >= from")
		}
		tz := viper.GetString("timezone")
		if tz == "local" {
			tz = time.Local.String()
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		rows := []map[string]any{}
		for d := start; !d.After(end); d = d.Add(24 * time.Hour) {
			day, err := cl.GetSleepDay(context.Background(), d.Format(layout), tz)
			if err != nil {
				return err
			}
				// Convert durations from seconds to hours for readability
			durationHrs := day.Duration / 3600
			deepHrs := day.DeepDuration / 3600
			remHrs := day.RemDuration / 3600

			rows = append(rows, map[string]any{
				"date":         day.Date,
				"score":        day.Score,
				"duration_hrs": float64(int(durationHrs*10)) / 10,
				"deep_hrs":     float64(int(deepHrs*10)) / 10,
				"rem_hrs":      float64(int(remHrs*10)) / 10,
				"tnt":          day.Tnt,
				"rhr":          day.SleepQuality.HeartRate.Current,
				"hrv":          day.SleepQuality.HRV.Current,
			})
		}
		rows = output.FilterFields(rows, viper.GetStringSlice("fields"))
		headers := []string{"date", "score", "duration_hrs", "deep_hrs", "rem_hrs", "rhr", "hrv", "tnt"}
		if len(viper.GetStringSlice("fields")) > 0 {
			headers = viper.GetStringSlice("fields")
		}
		return output.Print(output.Format(viper.GetString("output")), headers, rows)
	},
}

func init() {
	sleepRangeCmd.Flags().String("from", "", "start date YYYY-MM-DD")
	sleepRangeCmd.Flags().String("to", "", "end date YYYY-MM-DD")
	viper.BindPFlag("from", sleepRangeCmd.Flags().Lookup("from"))
	viper.BindPFlag("to", sleepRangeCmd.Flags().Lookup("to"))
	if sleepCmd != nil {
		sleepCmd.AddCommand(sleepRangeCmd)
	}
}
