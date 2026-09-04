package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// When every household member is in Away mode the device payload omits
// leftUserId, rightUserId and awaySides entirely. Device().Sides() therefore
// reports empty strings, which silently resolves to "no users" for any caller
// that iterates over it.
//
// This is why `away off --both` was a no-op: its loop skips empty user IDs, so
// with both slots empty it made zero API calls and still reported success. The
// bug only appeared in the off direction, because `away on --both` runs while
// everyone is still home and the fields are populated.
func TestDeviceSidesEmptyWhenEveryoneAway(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-a","currentDevice":{"id":"dev-1"}}}`))
	})
	mux.HandleFunc("/devices/dev-1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Captured from a live Pod 2 Pro with both sides away.
		w.Write([]byte(`{"result":{"deviceId":"dev-1"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("e", "p", "uid-a", "", "")
	c.BaseURL = srv.URL
	c.DeviceID = "dev-1"
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	sides, err := c.Device().Sides(context.Background())
	if err != nil {
		t.Fatalf("Sides: %v", err)
	}
	if sides.LeftUserID != "" || sides.RightUserID != "" {
		t.Fatalf("expected empty sides for the all-away payload, got %+v", sides)
	}
}

// Explicitly requesting side fields recovers IDs omitted by the unfiltered
// device response. User records then supply each target's details.
func TestHouseholdUserTargetsSurvivesEveryoneAway(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-a","currentDevice":{"id":"dev-1"}}}`))
	})
	mux.HandleFunc("/devices/dev-1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("filter") != "leftUserId,rightUserId,awaySides" {
			w.Write([]byte(`{"result":{"deviceId":"dev-1"}}`))
			return
		}
		w.Write([]byte(`{"result":{"leftUserId":"uid-a","rightUserId":"uid-b",
			"awaySides":{"leftUserId":"uid-a","rightUserId":"uid-b"}}}`))
	})
	mux.HandleFunc("/users/uid-a", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-a","firstName":"A","currentDevice":{"side":"left"}}}`))
	})
	mux.HandleFunc("/users/uid-b", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-b","firstName":"B","currentDevice":{"side":"right"}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("e", "p", "uid-a", "", "")
	c.BaseURL = srv.URL
	c.DeviceID = "dev-1"
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	targets, err := c.HouseholdUserTargets(context.Background())
	if err != nil {
		t.Fatalf("HouseholdUserTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 household users, got %d (%+v)", len(targets), targets)
	}
	if targets[0].UserID != "uid-a" || targets[0].Side != "left" || targets[1].UserID != "uid-b" || targets[1].Side != "right" {
		t.Fatalf("unexpected household targets: %+v", targets)
	}
}
