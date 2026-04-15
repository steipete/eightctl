package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
)

var metricsCmd = &cobra.Command{Use: "metrics", Short: "Sleep metrics and insights"}

var metricsTrendsCmd = &cobra.Command{Use: "trends", RunE: func(cmd *cobra.Command, args []string) error {
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
	tz, err := resolveAPITimezone(viper.GetString("timezone"))
	if err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	var out any
	if err := cl.Metrics().Trends(context.Background(), from, to, tz, &out); err != nil {
		return err
	}
	return output.Print(output.Format(viper.GetString("output")), []string{"trends"}, []map[string]any{{"trends": out}})
}}

var metricsIntervalsCmd = &cobra.Command{Use: "intervals", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	id, err := cmd.Flags().GetString("id")
	if err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	var out any
	if err := cl.Metrics().Intervals(context.Background(), id, &out); err != nil {
		return err
	}
	return output.Print(output.Format(viper.GetString("output")), []string{"interval"}, []map[string]any{{"interval": out}})
}}

var metricsInsightsCmd = &cobra.Command{Use: "insights", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	var out any
	if err := cl.Metrics().Insights(context.Background(), &out); err != nil {
		return err
	}
	return output.Print(output.Format(viper.GetString("output")), []string{"insights"}, []map[string]any{{"insights": out}})
}}

func init() {
	metricsTrendsCmd.Flags().String("from", "", "from date YYYY-MM-DD")
	metricsTrendsCmd.Flags().String("to", "", "to date YYYY-MM-DD")
	metricsIntervalsCmd.Flags().String("id", "", "session id")

	metricsCmd.AddCommand(metricsTrendsCmd, metricsIntervalsCmd, metricsInsightsCmd)
}
