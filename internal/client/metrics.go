package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

type MetricsActions struct{ c *Client }

func (c *Client) Metrics() *MetricsActions { return &MetricsActions{c: c} }

func (m *MetricsActions) Trends(ctx context.Context, from, to string, out any) error {
	if err := m.c.requireUser(ctx); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("from", from)
	q.Set("to", to)
	q.Set("include-main", "false")
	q.Set("include-all-sessions", "true")
	q.Set("model-version", "v2")
	path := fmt.Sprintf("/users/%s/trends", m.c.UserID)
	return m.c.do(ctx, http.MethodGet, path, q, nil, out)
}

func (m *MetricsActions) Intervals(ctx context.Context, sessionID string, out any) error {
	if err := m.c.requireUser(ctx); err != nil {
		return err
	}
	path := fmt.Sprintf("/users/%s/intervals/%s", m.c.UserID, sessionID)
	return m.c.do(ctx, http.MethodGet, path, nil, nil, out)
}

func (m *MetricsActions) Summary(ctx context.Context, out any) error {
	if err := m.c.requireUser(ctx); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("metrics", "all")
	path := fmt.Sprintf("/users/%s/metrics/summary", m.c.UserID)
	return m.c.do(ctx, http.MethodGet, path, q, nil, out)
}

func (m *MetricsActions) Aggregate(ctx context.Context, out any) error {
	if err := m.c.requireUser(ctx); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("v2", "true")
	q.Set("metrics", "all")
	path := fmt.Sprintf("/users/%s/metrics/aggregate", m.c.UserID)
	return m.c.do(ctx, http.MethodGet, path, q, nil, out)
}

func (m *MetricsActions) Insights(ctx context.Context, out any) error {
	if err := m.c.requireUser(ctx); err != nil {
		return err
	}
	path := fmt.Sprintf("/users/%s/insights", m.c.UserID)
	return m.c.do(ctx, http.MethodGet, path, nil, nil, out)
}
