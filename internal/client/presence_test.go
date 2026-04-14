package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPresenceFromTrendDays(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)

	t.Run("active session with recent heart rate", func(t *testing.T) {
		days := []trendDay{{
			PresenceStart: "2026-04-13T11:00:00Z",
			Sessions: []trendSession{{
				Timeseries: map[string][][]any{
					"heartRate": {{"2026-04-13T11:55:00Z", 60}},
				},
			}},
		}}
		if !presenceFromTrendDays(days, now) {
			t.Fatalf("expected presence to be true")
		}
	})

	t.Run("ended session is not present", func(t *testing.T) {
		days := []trendDay{{
			PresenceStart: "2026-04-13T02:00:00Z",
			PresenceEnd:   "2026-04-13T09:00:00Z",
			Sessions: []trendSession{{
				Timeseries: map[string][][]any{
					"heartRate": {{"2026-04-13T08:55:00Z", 55}},
				},
			}},
		}}
		if presenceFromTrendDays(days, now) {
			t.Fatalf("expected presence to be false")
		}
	})
}

func TestGetPresenceUsesTrendsEndpoint(t *testing.T) {
	var gotPath string
	var gotTZ string

	mux := http.NewServeMux()
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-123","devices":["dev-1"],"currentDevice":{"id":"dev-1"}}}`))
	})
	mux.HandleFunc("/users/uid-123/trends", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotTZ = r.URL.Query().Get("tz")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"days":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	present, err := c.GetPresence(context.Background(), "America/New_York")
	if err != nil {
		t.Fatalf("GetPresence: %v", err)
	}
	if present {
		t.Fatalf("expected no presence from empty trends response")
	}
	if gotPath != "/users/uid-123/trends" {
		t.Fatalf("path = %q, want /users/uid-123/trends", gotPath)
	}
	if gotTZ != "America/New_York" {
		t.Fatalf("tz = %q, want America/New_York", gotTZ)
	}
}
