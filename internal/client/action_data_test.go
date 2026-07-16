package client

import (
	"context"
	"net/http"
	"testing"
)

func TestClientDataActionEndpoints(t *testing.T) {
	tests := []actionEndpointTestCase{
		{
			name: "MetricsTrends",
			call: func(ctx context.Context, c *Client) error {
				var out any
				return c.Metrics().Trends(ctx, "2026-04-01", "2026-04-02", "UTC", &out)
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/trends"},
			wantQuery: map[string]string{
				"from":                 "2026-04-01",
				"to":                   "2026-04-02",
				"tz":                   "UTC",
				"include-main":         "false",
				"include-all-sessions": "true",
				"model-version":        "v2",
			},
		},
		{
			name: "MetricsIntervals",
			call: func(ctx context.Context, c *Client) error {
				var out any
				return c.Metrics().Intervals(ctx, "session-1", &out)
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/intervals/session-1"},
		},
		{
			name: "GetSmartSchedule",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetSmartSchedule(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/temperature"},
		},
		{
			name: "TempModeNapActivate",
			call: func(ctx context.Context, c *Client) error {
				return c.TempModes().NapActivate(ctx)
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/users/uid/temperature/nap-mode/activate"},
		},
		{
			name: "TempModeNapDeactivate",
			call: func(ctx context.Context, c *Client) error {
				return c.TempModes().NapDeactivate(ctx)
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/users/uid/temperature/nap-mode/deactivate"},
		},
		{
			name: "TempModeNapExtend",
			call: func(ctx context.Context, c *Client) error {
				return c.TempModes().NapExtend(ctx)
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/users/uid/temperature/nap-mode/extend"},
		},
		{
			name: "TempModeNapStatus",
			call: func(ctx context.Context, c *Client) error {
				var out any
				return c.TempModes().NapStatus(ctx, &out)
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/temperature/nap-mode/status"},
		},
		{
			name: "TempModeHotFlashActivate",
			call: func(ctx context.Context, c *Client) error {
				return c.TempModes().HotFlashActivate(ctx)
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/users/uid/temperature/hot-flash-mode/activate"},
		},
		{
			name: "TempModeHotFlashDeactivate",
			call: func(ctx context.Context, c *Client) error {
				return c.TempModes().HotFlashDeactivate(ctx)
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/users/uid/temperature/hot-flash-mode/deactivate"},
		},
		{
			name: "TempModeHotFlashStatus",
			call: func(ctx context.Context, c *Client) error {
				var out any
				return c.TempModes().HotFlashStatus(ctx, &out)
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/temperature/hot-flash-mode"},
		},
		{
			name: "TempEvents",
			call: func(ctx context.Context, c *Client) error {
				var out any
				return c.TempModes().TempEvents(ctx, "2026-04-01", "2026-04-02", &out)
			},
			want:      recordedRequest{Method: http.MethodGet, Path: "/users/uid/temp-events"},
			wantQuery: map[string]string{"from": "2026-04-01", "to": "2026-04-02"},
		},
		{
			name: "TravelTrips",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Travel().Trips(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/travel/trips"},
		},
		{
			name: "TravelCreateTrip",
			call: func(ctx context.Context, c *Client) error {
				return c.Travel().CreateTrip(ctx, map[string]any{"destination": "Vienna"})
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/travel/trips"},
			bodyHas: `"destination":"Vienna"`,
		},
		{
			name: "TravelCreatePlan",
			call: func(ctx context.Context, c *Client) error {
				return c.Travel().CreatePlan(ctx, "trip-1", map[string]any{"name": "Plan"})
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/travel/trips/trip-1/plans"},
			bodyHas: `"name":"Plan"`,
		},
		{
			name: "TravelUpdatePlan",
			call: func(ctx context.Context, c *Client) error {
				return c.Travel().UpdatePlan(ctx, "plan-1", map[string]any{"name": "Updated"})
			},
			want:    recordedRequest{Method: http.MethodPatch, Path: "/users/uid/travel/plans/plan-1"},
			bodyHas: `"name":"Updated"`,
		},
		{
			name: "TravelDeleteTrip",
			call: func(ctx context.Context, c *Client) error {
				return c.Travel().DeleteTrip(ctx, "trip-1")
			},
			want: recordedRequest{Method: http.MethodDelete, Path: "/users/uid/travel/trips/trip-1"},
		},
		{
			name: "TravelPlans",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Travel().Plans(ctx, "trip-1")
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/travel/trips/trip-1/plans"},
		},
		{
			name: "TravelPlanTasks",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Travel().PlanTasks(ctx, "plan-1")
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/travel/plans/plan-1/tasks"},
		},
		{
			name: "TravelAirportSearch",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Travel().AirportSearch(ctx, "VIE")
				return err
			},
			want:      recordedRequest{Method: http.MethodGet, Path: "/travel/airport-search"},
			wantQuery: map[string]string{"query": "VIE"},
		},
		{
			name: "TravelFlightStatus",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Travel().FlightStatus(ctx, "OS88")
				return err
			},
			want:      recordedRequest{Method: http.MethodGet, Path: "/travel/flight-status"},
			wantQuery: map[string]string{"flightNumber": "OS88"},
		},
		{
			name: "TurnOffForUser",
			call: func(ctx context.Context, c *Client) error {
				return c.TurnOffForUser(ctx, "uid")
			},
			want:    recordedRequest{Method: http.MethodPut, Path: "/v1/users/uid/temperature"},
			bodyHas: `"type":"off"`,
		},
		{
			name: "GetStatusForUser",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetStatusForUser(ctx, "uid")
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/v1/users/uid/temperature"},
		},
		{
			name: "GetSleepDay",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetSleepDay(ctx, "2026-04-22", "UTC")
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/trends"},
			wantQuery: map[string]string{
				"from":                 "2026-04-22",
				"to":                   "2026-04-22",
				"tz":                   "UTC",
				"include-main":         "false",
				"include-all-sessions": "true",
				"model-version":        "v2",
			},
		},
		{
			name: "ListTracks",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.ListTracks(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/audio/tracks"},
		},
		{
			name: "ReleaseFeatures",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.ReleaseFeatures(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/release/features"},
		},
	}
	assertActionEndpoints(t, tests)
}
