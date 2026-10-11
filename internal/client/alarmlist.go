package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/steipete/eightctl/internal/alarmguard"
)

// Alarm represents alarm payload.
type Alarm struct {
	ID         string  `json:"id"`
	Enabled    bool    `json:"enabled"`
	Time       string  `json:"time"`
	DaysOfWeek []int   `json:"daysOfWeek"`
	Vibration  bool    `json:"vibration"`
	Sound      *string `json:"sound,omitempty"`
}

// AlarmVibration describes the vibration wake component of a one-off alarm.
type AlarmVibration struct {
	Enabled    bool   `json:"enabled"`
	PowerLevel int    `json:"powerLevel"`
	Pattern    string `json:"pattern"`
}

// AlarmThermal describes the thermal wake component of a one-off alarm.
type AlarmThermal struct {
	Enabled bool `json:"enabled"`
	Level   int  `json:"level"`
}

// AlarmSmart describes the light-sleep wake window for a one-off alarm.
type AlarmSmart struct {
	LightSleepEnabled bool `json:"lightSleepEnabled"`
	SleepCapEnabled   bool `json:"sleepCapEnabled"`
	SleepCapMinutes   int  `json:"sleepCapMinutes"`
}

// OneOffAlarm models the proposed app-API payload for a single-use alarm.
// The provider contract still requires controlled-account verification.
type OneOffAlarm struct {
	CreationAttempt string         `json:"-"`
	ID              string         `json:"id,omitempty"`
	Enabled         bool           `json:"enabled"`
	Time            string         `json:"time"`
	NextTimestamp   string         `json:"nextTimestamp,omitempty"`
	Vibration       AlarmVibration `json:"vibration"`
	Thermal         AlarmThermal   `json:"thermal"`
	Smart           *AlarmSmart    `json:"smart,omitempty"`
}

func (c *Client) ListAlarms(ctx context.Context) ([]Alarm, error) {
	if err := c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/users/%s/alarms", c.UserID)
	var res struct {
		Alarms []Alarm `json:"alarms"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
		return nil, err
	}
	return res.Alarms, nil
}

func (c *Client) CreateAlarm(ctx context.Context, alarm Alarm) (*Alarm, error) {
	if err := c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/users/%s/alarms", c.UserID)
	var res struct {
		Alarm Alarm `json:"alarm"`
	}
	if err := c.do(ctx, http.MethodPost, path, nil, alarm, &res); err != nil {
		return nil, err
	}
	return &res.Alarm, nil
}

// CreateOneOffAlarm requests a single-use alarm through the app API.
// Unlike the recurring alarm endpoint, this payload has no weekday repeat
// configuration and uses nested vibration and thermal wake settings.
func (c *Client) CreateOneOffAlarm(ctx context.Context, alarm OneOffAlarm) (*OneOffAlarm, error) {
	return c.createOneOffAlarm(ctx, alarm, "")
}

// CreateNextOneOffAlarm deliberately starts a new creation after the latest
// confirmed attempt. A pending attempt cannot be acknowledged or bypassed.
func (c *Client) CreateNextOneOffAlarm(ctx context.Context, alarm OneOffAlarm, afterAttempt string) (*OneOffAlarm, error) {
	if afterAttempt == "" {
		return nil, fmt.Errorf("--after-attempt requires a confirmed attempt token")
	}
	return c.createOneOffAlarm(ctx, alarm, afterAttempt)
}

func (c *Client) createOneOffAlarm(ctx context.Context, alarm OneOffAlarm, afterAttempt string) (*OneOffAlarm, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.requireUser(ctx); err != nil {
		return nil, err
	}
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request, err := json.Marshal(alarm)
	if err != nil {
		return nil, err
	}
	store := c.alarmAttempts
	if store == nil {
		defaultStore, err := alarmguard.Default()
		if err != nil {
			return nil, err
		}
		store = &defaultStore
	}
	var created OneOffAlarm
	receipt, reused, err := store.Run(alarmguard.Scope(c.AppURL, c.UserID), request, afterAttempt, func() (string, error) {
		path := fmt.Sprintf("/v1/users/%s/alarms", c.UserID)
		var raw json.RawMessage
		if err := c.doAppOnce(ctx, path, alarm, &raw); err != nil {
			return "", err
		}
		var err error
		created, err = decodeOneOffAlarmResponse(raw)
		if err != nil {
			return "", err
		}
		return created.ID, nil
	})
	if err != nil {
		return nil, err
	}
	if reused {
		persisted, err := c.FindAlarmV2(ctx, receipt.AlarmID)
		if err != nil {
			return nil, &alarmguard.UncertainError{Attempt: receipt.Attempt, Cause: err}
		}
		created = *persisted
	}
	created.CreationAttempt = receipt.Attempt
	return &created, nil
}

func decodeOneOffAlarmResponse(data []byte) (OneOffAlarm, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return OneOffAlarm{}, err
	}
	if alarmData, ok := fields["alarm"]; ok && string(alarmData) != "null" {
		var alarm OneOffAlarm
		if err := json.Unmarshal(alarmData, &alarm); err != nil {
			return OneOffAlarm{}, err
		}
		return alarm, nil
	}
	var alarm OneOffAlarm
	if err := json.Unmarshal(data, &alarm); err != nil {
		return OneOffAlarm{}, err
	}
	return alarm, nil
}

// ListAlarmsV2 reads the app alarm representation used for Smart Alarm
// read-back. The endpoint contract is not yet verified against a controlled account.
func (c *Client) ListAlarmsV2(ctx context.Context) ([]OneOffAlarm, error) {
	if err := c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v2/users/%s/alarms", c.UserID)
	var res struct {
		Alarms []OneOffAlarm `json:"alarms"`
	}
	if err := c.doApp(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
		return nil, err
	}
	return res.Alarms, nil
}

// FindAlarmV2 returns one alarm from the current app alarm representation.
func (c *Client) FindAlarmV2(ctx context.Context, alarmID string) (*OneOffAlarm, error) {
	alarms, err := c.ListAlarmsV2(ctx)
	if err != nil {
		return nil, err
	}
	for _, alarm := range alarms {
		if alarm.ID == alarmID {
			return &alarm, nil
		}
	}
	return nil, fmt.Errorf("alarm %s was not found in the current alarm list", alarmID)
}

func (c *Client) UpdateAlarm(ctx context.Context, alarmID string, patch map[string]any) (*Alarm, error) {
	if err := c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/users/%s/alarms/%s", c.UserID, alarmID)
	var res struct {
		Alarm Alarm `json:"alarm"`
	}
	if err := c.do(ctx, http.MethodPatch, path, nil, patch, &res); err != nil {
		return nil, err
	}
	return &res.Alarm, nil
}

func (c *Client) DeleteAlarm(ctx context.Context, alarmID string) error {
	if err := c.requireUser(ctx); err != nil {
		return err
	}
	path := fmt.Sprintf("/users/%s/alarms/%s", c.UserID, alarmID)
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}
