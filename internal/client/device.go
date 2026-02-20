package client

import (
	"context"
	"fmt"
	"net/http"
)

type DeviceActions struct{ c *Client }

func (c *Client) Device() *DeviceActions { return &DeviceActions{c: c} }

// SideUserIDs returns the left and right user IDs from the device.
func (d *DeviceActions) SideUserIDs(ctx context.Context) (left, right string, err error) {
	id, err := d.c.EnsureDeviceID(ctx)
	if err != nil {
		return "", "", err
	}
	path := fmt.Sprintf("/devices/%s", id)
	var res struct {
		Result struct {
			LeftUserID  string `json:"leftUserId"`
			RightUserID string `json:"rightUserId"`
		} `json:"result"`
	}
	if err := d.c.do(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
		return "", "", err
	}
	return res.Result.LeftUserID, res.Result.RightUserID, nil
}

// UserIDForSide returns the user ID for "left", "right", or "partner" (the other side).
func (c *Client) UserIDForSide(ctx context.Context, side string) (string, error) {
	if side == "" || side == "me" {
		return c.UserID, nil
	}
	left, right, err := c.Device().SideUserIDs(ctx)
	if err != nil {
		return "", err
	}
	switch side {
	case "left":
		return left, nil
	case "right":
		return right, nil
	case "partner":
		if c.UserID == left {
			return right, nil
		}
		return left, nil
	default:
		return "", fmt.Errorf("invalid side %q: use left, right, partner, or me", side)
	}
}

func (d *DeviceActions) Info(ctx context.Context) (any, error) {
	id, err := d.c.EnsureDeviceID(ctx)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/devices/%s", id)
	var res any
	err = d.c.do(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (d *DeviceActions) Peripherals(ctx context.Context) (any, error) {
	id, err := d.c.EnsureDeviceID(ctx)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/devices/%s/peripherals", id)
	var res any
	err = d.c.do(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (d *DeviceActions) Owner(ctx context.Context) (any, error) {
	id, err := d.c.EnsureDeviceID(ctx)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/devices/%s/owner", id)
	var res any
	err = d.c.do(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (d *DeviceActions) Warranty(ctx context.Context) (any, error) {
	id, err := d.c.EnsureDeviceID(ctx)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/devices/%s/warranty", id)
	var res any
	err = d.c.do(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (d *DeviceActions) Online(ctx context.Context) (any, error) {
	id, err := d.c.EnsureDeviceID(ctx)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/devices/%s/online", id)
	var res any
	err = d.c.do(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (d *DeviceActions) PrimingTasks(ctx context.Context) (any, error) {
	id, err := d.c.EnsureDeviceID(ctx)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/devices/%s/priming/tasks", id)
	var res any
	err = d.c.do(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (d *DeviceActions) PrimingSchedule(ctx context.Context) (any, error) {
	id, err := d.c.EnsureDeviceID(ctx)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/devices/%s/priming/schedule", id)
	var res any
	err = d.c.do(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}
