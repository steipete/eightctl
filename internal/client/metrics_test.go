package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMetricsSummaryIncludesDefaultMetrics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users/uid/metrics/summary", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("metrics"); got != "all" {
			t.Fatalf("expected metrics=all, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	var out map[string]any
	if err := c.Metrics().Summary(context.Background(), &out); err != nil {
		t.Fatalf("summary: %v", err)
	}
}

func TestMetricsAggregateIncludesDefaultMetrics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users/uid/metrics/aggregate", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("metrics"); got != "all" {
			t.Fatalf("expected metrics=all, got %q", got)
		}
		if got := r.URL.Query().Get("v2"); got != "true" {
			t.Fatalf("expected v2=true, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	var out map[string]any
	if err := c.Metrics().Aggregate(context.Background(), &out); err != nil {
		t.Fatalf("aggregate: %v", err)
	}
}
