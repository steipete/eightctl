package client

import (
	"context"
	"fmt"
	"net/http"
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

// OneOffAlarm is the current app-API payload for a single-use alarm.
type OneOffAlarm struct {
	ID            string         `json:"id,omitempty"`
	Enabled       bool           `json:"enabled"`
	Time          string         `json:"time"`
	NextTimestamp string         `json:"nextTimestamp,omitempty"`
	Vibration     AlarmVibration `json:"vibration"`
	Thermal       AlarmThermal   `json:"thermal"`
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

// CreateOneOffAlarm creates a single-use alarm through the current app API.
// Unlike the recurring alarm endpoint, this payload has no weekday repeat
// configuration and uses nested vibration and thermal wake settings.
func (c *Client) CreateOneOffAlarm(ctx context.Context, alarm OneOffAlarm) (*OneOffAlarm, error) {
	if err := c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v1/users/%s/alarms", c.UserID)
	var res struct {
		Alarm OneOffAlarm `json:"alarm"`
	}
	if err := c.doApp(ctx, http.MethodPost, path, nil, alarm, &res); err != nil {
		return nil, err
	}
	return &res.Alarm, nil
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
