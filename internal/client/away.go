package client

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// SetAwayMode activates or deactivates away mode for a specific user ID.
// The away-mode endpoint lives on the app API (app-api.8slp.net), not the
// client API used by most other endpoints.
// If userID is empty, it defaults to the authenticated user.
func (c *Client) SetAwayMode(ctx context.Context, userID string, away bool) error {
	if userID == "" {
		if err := c.requireUser(ctx); err != nil {
			return err
		}
		userID = c.UserID
	}
	ts := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02T15:04:05.000Z")
	var payload map[string]any
	if away {
		payload = map[string]any{"awayPeriod": map[string]string{"start": ts}}
	} else {
		payload = map[string]any{"awayPeriod": map[string]string{"end": ts}}
	}
	u := fmt.Sprintf("%s/users/%s/away-mode", appAPIBaseURL, userID)
	return c.doURL(ctx, http.MethodPut, u, payload, nil)
}

// GetAwayMode reports whether away mode is currently active for a user.
// It reads the same app API endpoint SetAwayMode writes to, which answers
// with {"isAway": bool}. If userID is empty, it defaults to the
// authenticated user.
func (c *Client) GetAwayMode(ctx context.Context, userID string) (bool, error) {
	if userID == "" {
		if err := c.requireUser(ctx); err != nil {
			return false, err
		}
		userID = c.UserID
	}
	var res struct {
		IsAway *bool `json:"isAway"`
	}
	u := fmt.Sprintf("%s/users/%s/away-mode", appAPIBaseURL, userID)
	if err := c.doURL(ctx, http.MethodGet, u, nil, &res); err != nil {
		return false, err
	}
	if res.IsAway == nil {
		return false, fmt.Errorf("away mode response is missing isAway")
	}
	return *res.IsAway, nil
}
