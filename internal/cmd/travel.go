package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var travelCmd = &cobra.Command{Use: "travel", Short: "Travel / jetlag endpoints"}

var travelTripsCmd = &cobra.Command{Use: "trips", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Travel().Trips(context.Background())
	if err != nil {
		return err
	}
	return printRows([]string{"trips"}, []map[string]any{{"trips": res}})
}}

var travelCreateTripCmd = &cobra.Command{Use: "create-trip", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	body := map[string]any{}
	if v, _ := cmd.Flags().GetString("destination"); v != "" {
		body["destination"] = v
	}
	if v, _ := cmd.Flags().GetString("start-date"); v != "" {
		body["startDate"] = v
	}
	if v, _ := cmd.Flags().GetString("end-date"); v != "" {
		body["endDate"] = v
	}
	if v, _ := cmd.Flags().GetString("trip-timezone"); v != "" {
		body["timezone"] = v
	}
	if len(body) == 0 {
		return fmt.Errorf("provide at least --destination or --start-date/--end-date")
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Travel().CreateTrip(context.Background(), body)
}}

var travelDeleteTripCmd = &cobra.Command{Use: "delete-trip", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	id, _ := cmd.Flags().GetString("trip")
	if id == "" {
		return fmt.Errorf("--trip required")
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Travel().DeleteTrip(context.Background(), id)
}}

var travelPlansCmd = &cobra.Command{Use: "plans", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	trip, _ := cmd.Flags().GetString("trip")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Travel().Plans(context.Background(), trip)
	if err != nil {
		return err
	}
	return printRows([]string{"plans"}, []map[string]any{{"plans": res}})
}}

var travelCreatePlanCmd = &cobra.Command{Use: "create-plan", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	trip, _ := cmd.Flags().GetString("trip")
	if trip == "" {
		return fmt.Errorf("--trip required")
	}
	body := map[string]any{}
	if v, _ := cmd.Flags().GetString("name"); v != "" {
		body["name"] = v
	}
	if v, _ := cmd.Flags().GetString("date"); v != "" {
		body["date"] = v
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Travel().CreatePlan(context.Background(), trip, body)
}}

var travelUpdatePlanCmd = &cobra.Command{Use: "update-plan", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	plan, _ := cmd.Flags().GetString("plan")
	if plan == "" {
		return fmt.Errorf("--plan required")
	}
	patch := map[string]any{}
	if v, _ := cmd.Flags().GetString("name"); v != "" {
		patch["name"] = v
	}
	if v, _ := cmd.Flags().GetString("date"); v != "" {
		patch["date"] = v
	}
	if len(patch) == 0 {
		return fmt.Errorf("no fields to update")
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Travel().UpdatePlan(context.Background(), plan, patch)
}}

var travelTasksCmd = &cobra.Command{Use: "tasks", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	plan, _ := cmd.Flags().GetString("plan")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Travel().PlanTasks(context.Background(), plan)
	if err != nil {
		return err
	}
	return printRows([]string{"tasks"}, []map[string]any{{"tasks": res}})
}}

var travelAirportCmd = &cobra.Command{Use: "airport-search", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	query, _ := cmd.Flags().GetString("query")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Travel().AirportSearch(context.Background(), query)
	if err != nil {
		return err
	}
	return printRows([]string{"airports"}, []map[string]any{{"airports": res}})
}}

var travelFlightCmd = &cobra.Command{Use: "flight-status", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	flight, _ := cmd.Flags().GetString("flight")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Travel().FlightStatus(context.Background(), flight)
	if err != nil {
		return err
	}
	return printRows([]string{"flight"}, []map[string]any{{"flight": res}})
}}

func init() {
	travelPlansCmd.Flags().String("trip", "", "trip id")
	travelTasksCmd.Flags().String("plan", "", "plan id")
	travelAirportCmd.Flags().String("query", "", "airport query")
	travelFlightCmd.Flags().String("flight", "", "flight number")
	travelCreateTripCmd.Flags().String("destination", "", "destination")
	travelCreateTripCmd.Flags().String("start-date", "", "start date")
	travelCreateTripCmd.Flags().String("end-date", "", "end date")
	// Named --trip-timezone (not --timezone) so the CLI's persistent --timezone
	// flag for output/formatting is not shadowed on this subcommand.
	travelCreateTripCmd.Flags().String("trip-timezone", "", "IANA timezone for the trip destination")
	travelDeleteTripCmd.Flags().String("trip", "", "trip id")
	travelCreatePlanCmd.Flags().String("trip", "", "trip id")
	travelCreatePlanCmd.Flags().String("name", "", "plan name")
	travelCreatePlanCmd.Flags().String("date", "", "plan date")
	travelUpdatePlanCmd.Flags().String("plan", "", "plan id")
	travelUpdatePlanCmd.Flags().String("name", "", "plan name")
	travelUpdatePlanCmd.Flags().String("date", "", "plan date")

	travelCmd.AddCommand(
		travelTripsCmd,
		travelCreateTripCmd,
		travelDeleteTripCmd,
		travelPlansCmd,
		travelCreatePlanCmd,
		travelUpdatePlanCmd,
		travelTasksCmd,
		travelAirportCmd,
		travelFlightCmd,
	)
}
