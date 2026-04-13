package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResolveHouseholdSideLeftRight(t *testing.T) {
	targets := []HouseholdUserTarget{
		{UserID: "left-user", Side: "left", FirstName: "Lefty"},
		{UserID: "right-user", Side: "right", FirstName: "Righty"},
	}

	target, err := ResolveHouseholdSide(targets, "right")
	if err != nil {
		t.Fatalf("ResolveHouseholdSide: %v", err)
	}
	if target.UserID != "right-user" {
		t.Fatalf("user id = %q, want right-user", target.UserID)
	}
}

func TestResolveHouseholdSideSolo(t *testing.T) {
	target, err := ResolveHouseholdSide([]HouseholdUserTarget{
		{UserID: "solo-user", Side: "solo"},
	}, "solo")
	if err != nil {
		t.Fatalf("ResolveHouseholdSide: %v", err)
	}
	if target.UserID != "solo-user" {
		t.Fatalf("user id = %q, want solo-user", target.UserID)
	}
}

func TestResolveHouseholdSideUnavailable(t *testing.T) {
	_, err := ResolveHouseholdSide([]HouseholdUserTarget{
		{UserID: "solo-user", Side: "solo"},
	}, "right")
	if err == nil {
		t.Fatalf("expected side resolution error")
	}
	if !strings.Contains(err.Error(), `side "right" is not available`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveHouseholdSideUnknownMapping(t *testing.T) {
	_, err := ResolveHouseholdSide([]HouseholdUserTarget{
		{UserID: "mystery-user"},
	}, "left")
	if err == nil {
		t.Fatalf("expected unknown mapping error")
	}
	if !strings.Contains(err.Error(), "could not resolve household side mapping") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHouseholdUserTargets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"devices":["dev-1"]}}`))
	})
	mux.HandleFunc("/devices/dev-1", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("filter"); got != "leftUserId,rightUserId,awaySides" {
			t.Fatalf("filter = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":{"leftUserId":"left-user","rightUserId":"right-user"}}`))
	})
	mux.HandleFunc("/users/left-user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"left-user","firstName":"Igor","lastName":"Left","email":"left@example.com","currentDevice":{"side":"left"}}}`))
	})
	mux.HandleFunc("/users/right-user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"right-user","firstName":"Renata","lastName":"Right","email":"right@example.com","currentDevice":{"side":"right"}}}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	targets, err := c.HouseholdUserTargets(context.Background())
	if err != nil {
		t.Fatalf("HouseholdUserTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2", len(targets))
	}
	if targets[0].UserID != "left-user" || targets[0].Side != "left" {
		t.Fatalf("unexpected left target: %+v", targets[0])
	}
	if targets[1].UserID != "right-user" || targets[1].Side != "right" {
		t.Fatalf("unexpected right target: %+v", targets[1])
	}
}

func TestHouseholdUserTargetsInfersSoloWhenOnlyOneUserExists(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"devices":["dev-1"]}}`))
	})
	mux.HandleFunc("/devices/dev-1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":{"leftUserId":"solo-user"}}`))
	})
	mux.HandleFunc("/users/solo-user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"solo-user","firstName":"Solo","lastName":"Sleeper","email":"solo@example.com","currentDevice":{}}}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	targets, err := c.HouseholdUserTargets(context.Background())
	if err != nil {
		t.Fatalf("HouseholdUserTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Side != "solo" {
		t.Fatalf("side = %q, want solo", targets[0].Side)
	}
}
