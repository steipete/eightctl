package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type trendSample struct {
	Days []trendDay `json:"days"`
}

type trendDay struct {
	Day           string         `json:"day"`
	PresenceStart string         `json:"presenceStart"`
	PresenceEnd   string         `json:"presenceEnd"`
	Sessions      []trendSession `json:"sessions"`
}

type trendSession struct {
	Timeseries map[string][][]any `json:"timeseries"`
}

func (c *Client) GetPresence(ctx context.Context, from, to, timezone string) (bool, error) {
	if err := c.requireUser(ctx); err != nil {
		return false, err
	}

	now := time.Now()
	from, to = resolvePresenceWindow(now, from, to)
	q := url.Values{}
	q.Set("tz", resolveTZ(timezone))
	q.Set("from", from)
	q.Set("to", to)
	q.Set("include-main", "false")
	q.Set("include-all-sessions", "true")
	q.Set("model-version", "v2")

	path := fmt.Sprintf("/users/%s/trends", c.UserID)
	var res trendSample
	if err := c.do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
		return false, err
	}
	return presenceFromTrendDays(res.Days, now.UTC()), nil
}

func resolvePresenceWindow(now time.Time, from, to string) (string, string) {
	const layout = "2006-01-02"

	if from == "" && to == "" {
		return now.Add(-24 * time.Hour).Format(layout), now.Format(layout)
	}
	if to == "" {
		return from, now.Format(layout)
	}
	if from == "" {
		end, err := time.Parse(layout, to)
		if err != nil {
			return from, to
		}
		return end.Add(-24 * time.Hour).Format(layout), to
	}
	return from, to
}

func presenceFromTrendDays(days []trendDay, now time.Time) bool {
	for i := len(days) - 1; i >= 0; i-- {
		day := days[i]
		if ts, ok := latestHeartRateTimestamp(day); ok {
			age := now.Sub(ts)
			if age >= 0 && age <= 10*time.Minute {
				return true
			}
			if day.PresenceEnd == "" && age >= 0 && age <= 30*time.Minute {
				return true
			}
		}
		if day.PresenceStart != "" {
			return day.PresenceEnd == ""
		}
	}
	return false
}

func latestHeartRateTimestamp(day trendDay) (time.Time, bool) {
	for i := len(day.Sessions) - 1; i >= 0; i-- {
		samples := day.Sessions[i].Timeseries["heartRate"]
		for j := len(samples) - 1; j >= 0; j-- {
			if len(samples[j]) == 0 {
				continue
			}
			rawTS, ok := samples[j][0].(string)
			if !ok || rawTS == "" {
				continue
			}
			ts, err := time.Parse(time.RFC3339Nano, rawTS)
			if err != nil {
				continue
			}
			return ts.UTC(), true
		}
	}
	return time.Time{}, false
}
