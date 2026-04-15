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
		from, err := cmd.Flags().GetString("from")
		if err != nil {
			return err
		}
		to, err := cmd.Flags().GetString("to")
		if err != nil {
			return err
		}
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
		tz, err := resolveAPITimezone(viper.GetString("timezone"))
		if err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		rows := []map[string]any{}
		for d := start; !d.After(end); d = d.Add(24 * time.Hour) {
			day, err := cl.GetSleepDay(context.Background(), d.Format(layout), tz)
			if err != nil {
				return err
			}
			rows = append(rows, map[string]any{
				"date":       day.Date,
				"score":      day.Score,
				"duration":   day.Duration,
				"tnt":        day.Tnt,
				"resp_rate":  day.Respiratory,
				"heart_rate": day.HeartRate,
				"hrv_score":  day.SleepQuality.HRV.Score,
			})
		}
		rows = output.FilterFields(rows, viper.GetStringSlice("fields"))
		headers := []string{"date", "score", "duration", "tnt", "resp_rate", "heart_rate", "hrv_score"}
		if len(viper.GetStringSlice("fields")) > 0 {
			headers = viper.GetStringSlice("fields")
		}
		return output.Print(output.Format(viper.GetString("output")), headers, rows)
	},
}

func init() {
	sleepRangeCmd.Flags().String("from", "", "start date YYYY-MM-DD")
	sleepRangeCmd.Flags().String("to", "", "end date YYYY-MM-DD")
	if sleepCmd != nil {
		sleepCmd.AddCommand(sleepRangeCmd)
	}
}
