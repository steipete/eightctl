package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

type MetricsActions struct{ c *Client }

func (c *Client) Metrics() *MetricsActions { return &MetricsActions{c: c} }

func (m *MetricsActions) Trends(ctx context.Context, from, to, tz string, out any) error {
	if err := m.c.requireUser(ctx); err != nil {
		return err
	}
	q := url.Values{}
	if from != "" {
		q.Set("from", from)
	}
	if to != "" {
		q.Set("to", to)
	}
	q.Set("tz", resolveTZ(tz))
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
