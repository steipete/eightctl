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
	var gotFrom string
	var gotTo string

	mux := http.NewServeMux()
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-123","devices":["dev-1"],"currentDevice":{"id":"dev-1"}}}`))
	})
	mux.HandleFunc("/users/uid-123/trends", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotTZ = r.URL.Query().Get("tz")
		gotFrom = r.URL.Query().Get("from")
		gotTo = r.URL.Query().Get("to")
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

	present, err := c.GetPresence(context.Background(), "", "", "America/New_York")
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
	if gotFrom == "" || gotTo == "" {
		t.Fatalf("expected default from/to range, got from=%q to=%q", gotFrom, gotTo)
	}
}

func TestGetPresenceUsesProvidedDateRange(t *testing.T) {
	var gotFrom string
	var gotTo string

	mux := http.NewServeMux()
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-123","devices":["dev-1"],"currentDevice":{"id":"dev-1"}}}`))
	})
	mux.HandleFunc("/users/uid-123/trends", func(w http.ResponseWriter, r *http.Request) {
		gotFrom = r.URL.Query().Get("from")
		gotTo = r.URL.Query().Get("to")
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

	_, err := c.GetPresence(context.Background(), "2026-04-01", "2026-04-17", "America/New_York")
	if err != nil {
		t.Fatalf("GetPresence: %v", err)
	}
	if gotFrom != "2026-04-01" {
		t.Fatalf("from = %q, want 2026-04-01", gotFrom)
	}
	if gotTo != "2026-04-17" {
		t.Fatalf("to = %q, want 2026-04-17", gotTo)
	}
}

func TestResolvePresenceWindow(t *testing.T) {
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)

	t.Run("defaults to last day", func(t *testing.T) {
		from, to := resolvePresenceWindow(now, "", "")
		if from != "2026-04-16" || to != "2026-04-17" {
			t.Fatalf("range = %q..%q, want 2026-04-16..2026-04-17", from, to)
		}
	})

	t.Run("fills missing to with today", func(t *testing.T) {
		from, to := resolvePresenceWindow(now, "2026-04-01", "")
		if from != "2026-04-01" || to != "2026-04-17" {
			t.Fatalf("range = %q..%q, want 2026-04-01..2026-04-17", from, to)
		}
	})

	t.Run("fills missing from from end date", func(t *testing.T) {
		from, to := resolvePresenceWindow(now, "", "2026-04-17")
		if from != "2026-04-16" || to != "2026-04-17" {
			t.Fatalf("range = %q..%q, want 2026-04-16..2026-04-17", from, to)
		}
	})
}
