package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

type HouseholdActions struct{ c *Client }

func (c *Client) Household() *HouseholdActions { return &HouseholdActions{c: c} }

func (h *HouseholdActions) Summary(ctx context.Context) (any, error) {
	if err := h.c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v1/household/users/%s/summary", h.c.UserID)
	var res any
	err := h.c.doApp(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (h *HouseholdActions) Schedule(ctx context.Context) (any, error) {
	if err := h.c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v1/household/users/%s/schedule", h.c.UserID)
	var res any
	err := h.c.doApp(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (h *HouseholdActions) CurrentSet(ctx context.Context) (any, error) {
	if err := h.c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v1/household/users/%s/current-set", h.c.UserID)
	var res any
	err := h.c.doApp(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (h *HouseholdActions) Invitations(ctx context.Context) (any, error) {
	if err := h.c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v1/household/users/%s/invitations", h.c.UserID)
	var res any
	err := h.c.doApp(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (h *HouseholdActions) Devices(ctx context.Context) (any, error) {
	if err := h.c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v1/household/users/%s/summary", h.c.UserID)
	var res struct {
		Households []struct {
			Sets []struct {
				Devices []map[string]any `json:"devices"`
			} `json:"sets"`
		} `json:"households"`
	}
	err := h.c.doApp(ctx, http.MethodGet, path, nil, nil, &res)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, household := range res.Households {
		for _, set := range household.Sets {
			out = append(out, set.Devices...)
		}
	}
	return out, nil
}

func (h *HouseholdActions) Users(ctx context.Context) (any, error) {
	targets, err := h.c.HouseholdUserTargets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(targets))
	for _, target := range targets {
		out = append(out, map[string]any{
			"userId":    target.UserID,
			"firstName": target.FirstName,
			"lastName":  target.LastName,
			"email":     target.Email,
			"side":      target.Side,
		})
	}
	return out, nil
}

func (h *HouseholdActions) Guests(ctx context.Context) (any, error) {
	if err := h.c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v1/household/users/%s/guests", h.c.UserID)
	var res any
	err := h.c.doApp(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func mapToValues(values map[string]string) url.Values {
	out := make(url.Values, len(values))
	for key, value := range values {
		out.Set(key, value)
	}
	return out
}

func orderedUniqueStrings(values ...string) []string {
	out := []string{}
	for _, value := range values {
		out = appendUniqueString(out, value)
	}
	return out
}

func appendUniqueString(existing []string, value string) []string {
	if value == "" {
		return existing
	}
	for _, current := range existing {
		if current == value {
			return existing
		}
	}
	return append(existing, value)
}
