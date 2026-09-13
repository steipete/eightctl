package client

import (
	"context"
	"fmt"
	"net/http"
)

// TurnOn powers device on.
func (c *Client) TurnOn(ctx context.Context) error {
	return c.TurnOnForUser(ctx, "")
}

// TurnOff powers device off.
func (c *Client) TurnOff(ctx context.Context) error {
	return c.TurnOffForUser(ctx, "")
}

func (c *Client) TurnOnForUser(ctx context.Context, userID string) error {
	return c.setPowerForUser(ctx, userID, true)
}

func (c *Client) TurnOffForUser(ctx context.Context, userID string) error {
	return c.setPowerForUser(ctx, userID, false)
}

func (c *Client) setPowerForUser(ctx context.Context, userID string, on bool) error {
	targetUserID := userID
	if targetUserID == "" {
		if err := c.requireUser(ctx); err != nil {
			return err
		}
		targetUserID = c.UserID
	}
	path := fmt.Sprintf("/v1/users/%s/temperature", targetUserID)
	state := "off"
	if on {
		state = "smart"
	}
	body := map[string]any{"currentState": map[string]string{"type": state}}
	return c.doApp(ctx, http.MethodPut, path, nil, body, nil)
}

// SetTemperature sets target heating/cooling level (-100..100) for the
// authenticated user's current pod side.
func (c *Client) SetTemperature(ctx context.Context, level int) error {
	return c.SetTemperatureForUser(ctx, "", level)
}

// SetTemperatureForUser sets target heating/cooling level (-100..100) for a
// specific household user ID. If userID is empty, the authenticated user's ID
// is resolved and used.
func (c *Client) SetTemperatureForUser(ctx context.Context, userID string, level int) error {
	if level < -100 || level > 100 {
		return fmt.Errorf("level must be between -100 and 100")
	}
	targetUserID := userID
	if targetUserID == "" {
		if err := c.requireUser(ctx); err != nil {
			return err
		}
		targetUserID = c.UserID
	}
	path := fmt.Sprintf("/v1/users/%s/temperature", targetUserID)
	if err := c.doApp(ctx, http.MethodPut, path, nil, map[string]any{
		"currentState": map[string]string{"type": "smart"},
	}, nil); err != nil {
		return err
	}
	body := map[string]int{"currentLevel": level}
	return c.doApp(ctx, http.MethodPut, path, nil, body, nil)
}

// TempStatus represents current temperature state payload.
type TempStatus struct {
	CurrentLevel int `json:"currentLevel"`
	CurrentState struct {
		Type string `json:"type"`
	} `json:"currentState"`
}

// GetStatus fetches temperature-based status (current mode/level).
func (c *Client) GetStatus(ctx context.Context) (*TempStatus, error) {
	return c.GetStatusForUser(ctx, "")
}

func (c *Client) GetStatusForUser(ctx context.Context, userID string) (*TempStatus, error) {
	targetUserID := userID
	if targetUserID == "" {
		if err := c.requireUser(ctx); err != nil {
			return nil, err
		}
		targetUserID = c.UserID
	}
	path := fmt.Sprintf("/v1/users/%s/temperature", targetUserID)
	var res TempStatus
	if err := c.doApp(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
