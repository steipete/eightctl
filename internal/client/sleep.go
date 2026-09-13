package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"charm.land/log/v2"
)

// SleepDay represents aggregated sleep metrics for a day.
type SleepDay struct {
	Date          string  `json:"day"`
	Score         float64 `json:"score"`
	Tnt           int     `json:"tnt"`
	Respiratory   float64 `json:"respiratoryRate"`
	HeartRate     float64 `json:"heartRate"`
	LatencyAsleep float64 `json:"latencyAsleepSeconds"`
	LatencyOut    float64 `json:"latencyOutSeconds"`
	Duration      float64 `json:"sleepDurationSeconds"`
	Stages        []Stage `json:"stages"`
	SleepQuality  struct {
		HRV struct {
			Score float64 `json:"score"`
		} `json:"hrv"`
		Resp struct {
			Score float64 `json:"score"`
		} `json:"respiratoryRate"`
	} `json:"sleepQualityScore"`
}

// Stage represents sleep stage duration.
type Stage struct {
	Stage    string  `json:"stage"`
	Duration float64 `json:"duration"`
}

// GetSleepDay fetches sleep trends for a date (YYYY-MM-DD).
func (c *Client) GetSleepDay(ctx context.Context, date string, timezone string) (*SleepDay, error) {
	if err := c.requireUser(ctx); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("tz", resolveTZ(timezone))
	q.Set("from", date)
	q.Set("to", date)
	q.Set("include-main", "false")
	q.Set("include-all-sessions", "true")
	q.Set("model-version", "v2")
	path := fmt.Sprintf("/users/%s/trends", c.UserID)
	var res struct {
		Days []SleepDay `json:"days"`
	}
	if err := c.do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
		return nil, err
	}
	if len(res.Days) == 0 {
		return nil, fmt.Errorf("no sleep data for %s", date)
	}
	return &res.Days[0], nil
}

// resolveTZ converts the CLI-convention zone "" or "local" to an IANA zone
// name. Eight Sleep's tz param rejects the literal strings "local" and
// "Local" (the latter is what time.Local.String() returns when the system
// has no zoneinfo). UTC is used as a last-resort fallback and logged so
// off-by-hours trend data is not presented as correct.
func resolveTZ(tz string) string {
	if tz != "" && tz != "local" {
		return tz
	}
	name := time.Local.String()
	if name == "" || name == "Local" {
		log.Warn("system timezone unresolved; defaulting to UTC. Pass --timezone <IANA> to override.")
		return "UTC"
	}
	return name
}
