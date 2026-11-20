package client

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestClientCoreActionEndpoints(t *testing.T) {
	tests := []actionEndpointTestCase{
		{
			name: "ListAlarms",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.ListAlarms(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/alarms"},
		},
		{
			name: "CreateAlarm",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.CreateAlarm(ctx, Alarm{Time: "07:00", Enabled: true})
				return err
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/alarms"},
			bodyHas: `"time":"07:00"`,
		},
		{
			name: "CreateOneOffAlarm",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.CreateOneOffAlarm(ctx, OneOffAlarm{
					Time:    "08:30:00",
					Enabled: true,
					Vibration: AlarmVibration{
						Enabled:    true,
						PowerLevel: 50,
						Pattern:    "RISE",
					},
					Thermal: AlarmThermal{
						Enabled: true,
						Level:   -10,
					},
				})
				return err
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/v1/users/uid/alarms"},
			bodyHas: `"thermal":{"enabled":true,"level":-10}`,
		},
		{
			name: "UpdateAlarm",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.UpdateAlarm(ctx, "alarm-1", map[string]any{"enabled": false})
				return err
			},
			want:    recordedRequest{Method: http.MethodPatch, Path: "/users/uid/alarms/alarm-1"},
			bodyHas: `"enabled":false`,
		},
		{
			name: "DeleteAlarm",
			call: func(ctx context.Context, c *Client) error {
				return c.DeleteAlarm(ctx, "alarm-1")
			},
			want: recordedRequest{Method: http.MethodDelete, Path: "/users/uid/alarms/alarm-1"},
		},
		{
			name: "AlarmSnooze",
			call: func(ctx context.Context, c *Client) error {
				return c.Alarms().Snooze(ctx, "alarm-1")
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/users/uid/alarms/alarm-1/snooze"},
		},
		{
			name: "AlarmDismiss",
			call: func(ctx context.Context, c *Client) error {
				return c.Alarms().Dismiss(ctx, "alarm-1")
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/users/uid/alarms/alarm-1/dismiss"},
		},
		{
			name: "AlarmDismissAll",
			call: func(ctx context.Context, c *Client) error {
				return c.Alarms().DismissAll(ctx)
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/users/uid/alarms/active/dismiss-all"},
		},
		{
			name: "AlarmVibrationTest",
			call: func(ctx context.Context, c *Client) error {
				return c.Alarms().VibrationTest(ctx)
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/users/uid/vibration-test"},
		},
		{
			name: "AudioTracks",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Audio().Tracks(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/audio/tracks"},
		},
		{
			name: "AudioCategories",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Audio().Categories(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/audio/categories"},
		},
		{
			name: "AudioPlayerState",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Audio().PlayerState(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/audio/player/state"},
		},
		{
			name: "AudioPlay",
			call: func(ctx context.Context, c *Client) error {
				return c.Audio().Play(ctx, "track-1")
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/audio/player"},
			bodyHas: `"trackId":"track-1"`,
		},
		{
			name: "AudioPause",
			call: func(ctx context.Context, c *Client) error {
				return c.Audio().Pause(ctx)
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/audio/player"},
			bodyHas: `"action":"pause"`,
		},
		{
			name: "AudioSeek",
			call: func(ctx context.Context, c *Client) error {
				return c.Audio().Seek(ctx, 1200)
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/audio/player/seek"},
			bodyHas: `"position":1200`,
		},
		{
			name: "AudioVolume",
			call: func(ctx context.Context, c *Client) error {
				return c.Audio().Volume(ctx, 44)
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/audio/player/volume"},
			bodyHas: `"level":44`,
		},
		{
			name: "AudioPair",
			call: func(ctx context.Context, c *Client) error {
				return c.Audio().Pair(ctx)
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/devices/dev/audio/player/pair"},
		},
		{
			name: "AudioRecommendedNext",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Audio().RecommendedNext(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/audio/tracks/recommended-next-track"},
		},
		{
			name: "AudioFavorites",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Audio().Favorites(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/audio/tracks/favorites"},
		},
		{
			name: "AudioAddFavorite",
			call: func(ctx context.Context, c *Client) error {
				return c.Audio().AddFavorite(ctx, "track-1")
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/audio/tracks/favorites"},
			bodyHas: `"trackId":"track-1"`,
		},
		{
			name: "AudioRemoveFavorite",
			call: func(ctx context.Context, c *Client) error {
				return c.Audio().RemoveFavorite(ctx, "track-1")
			},
			want: recordedRequest{Method: http.MethodDelete, Path: "/users/uid/audio/tracks/favorites/track-1"},
		},
		{
			name: "AutopilotDetails",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Autopilot().Details(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/autopilotDetails"},
		},
		{
			name: "AutopilotHistory",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Autopilot().History(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/autopilot-history"},
		},
		{
			name: "AutopilotRecap",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Autopilot().Recap(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/autopilotDetails/autopilotRecap"},
		},
		{
			name: "AutopilotSetLevelSuggestions",
			call: func(ctx context.Context, c *Client) error {
				return c.Autopilot().SetLevelSuggestions(ctx, true)
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/level-suggestions-mode"},
			bodyHas: `"enabled":true`,
		},
		{
			name: "AutopilotSetSnoreMitigation",
			call: func(ctx context.Context, c *Client) error {
				return c.Autopilot().SetSnoreMitigation(ctx, false)
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/autopilotDetails/snoringMitigation"},
			bodyHas: `"enabled":false`,
		},
		{
			name: "BaseInfo",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Base().Info(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/base"},
		},
		{
			name: "BaseSetAngle",
			call: func(ctx context.Context, c *Client) error {
				return c.Base().SetAngle(ctx, 3, 4)
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/base/angle"},
			bodyHas: `"foot":4`,
		},
		{
			name: "BasePresets",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Base().Presets(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/users/uid/base/presets"},
		},
		{
			name: "BaseRunPreset",
			call: func(ctx context.Context, c *Client) error {
				return c.Base().RunPreset(ctx, "flat")
			},
			want:    recordedRequest{Method: http.MethodPost, Path: "/users/uid/base/presets"},
			bodyHas: `"name":"flat"`,
		},
		{
			name: "BaseVibrationTest",
			call: func(ctx context.Context, c *Client) error {
				return c.Base().VibrationTest(ctx)
			},
			want: recordedRequest{Method: http.MethodPost, Path: "/devices/dev/vibration-test"},
		},
		{
			name: "DeviceInfo",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Device().Info(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/devices/dev"},
		},
		{
			name: "DevicePeripherals",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Device().Peripherals(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/devices/dev/peripherals"},
		},
		{
			name: "DeviceOwner",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Device().Owner(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/devices/dev/owner"},
		},
		{
			name: "DeviceWarranty",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Device().Warranty(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/devices/dev/warranty"},
		},
		{
			name: "DeviceOnline",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Device().Online(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/devices/dev/online"},
		},
		{
			name: "DevicePrimingTasks",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Device().PrimingTasks(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/devices/dev/priming/tasks"},
		},
		{
			name: "DevicePrimingSchedule",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Device().PrimingSchedule(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/devices/dev/priming/schedule"},
		},
		{
			name: "HouseholdSummary",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Household().Summary(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/v1/household/users/uid/summary"},
		},
		{
			name: "HouseholdSchedule",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Household().Schedule(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/v1/household/users/uid/schedule"},
		},
		{
			name: "HouseholdCurrentSet",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Household().CurrentSet(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/v1/household/users/uid/current-set"},
		},
		{
			name: "HouseholdInvitations",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Household().Invitations(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/v1/household/users/uid/invitations"},
		},
		{
			name: "HouseholdDevices",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Household().Devices(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/v1/household/users/uid/summary"},
		},
		{
			name: "HouseholdGuests",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Household().Guests(ctx)
				return err
			},
			want: recordedRequest{Method: http.MethodGet, Path: "/v1/household/users/uid/guests"},
		},
	}
	assertActionEndpoints(t, tests)
}

func TestCreateOneOffAlarmReturnsNestedResponse(t *testing.T) {
	c, _, cleanup := newRecordingClient(t)
	defer cleanup()

	got, err := c.CreateOneOffAlarm(context.Background(), OneOffAlarm{
		Time:    "08:30:00",
		Enabled: true,
		Vibration: AlarmVibration{
			Enabled:    true,
			PowerLevel: 50,
			Pattern:    "RISE",
		},
		Thermal: AlarmThermal{Enabled: true, Level: -10},
	})
	if err != nil {
		t.Fatalf("CreateOneOffAlarm: %v", err)
	}
	if got.ID != "one-off-alarm" || got.Time != "08:30:00" {
		t.Fatalf("alarm = %#v, want returned ID and time", got)
	}
	if got.Thermal.Level != -10 || !got.Thermal.Enabled {
		t.Fatalf("thermal = %#v, want enabled level -10", got.Thermal)
	}
}

func TestCreateOneOffAlarmPayload(t *testing.T) {
	c, records, cleanup := newRecordingClient(t)
	defer cleanup()

	_, err := c.CreateOneOffAlarm(context.Background(), OneOffAlarm{
		Time:    "08:30:00",
		Enabled: true,
		Vibration: AlarmVibration{
			Enabled:    true,
			PowerLevel: 50,
			Pattern:    "RISE",
		},
		Thermal: AlarmThermal{Enabled: true, Level: -10},
	})
	if err != nil {
		t.Fatalf("CreateOneOffAlarm: %v", err)
	}

	body := (*records)[0].Body
	for _, want := range []string{
		`"time":"08:30:00"`,
		`"vibration":{"enabled":true,"powerLevel":50,"pattern":"RISE"}`,
		`"thermal":{"enabled":true,"level":-10}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body = %q, missing %q", body, want)
		}
	}
}
