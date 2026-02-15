package client

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockServer builds a test server that can serve a handful of endpoints the client expects.
func mockServer(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-123","currentDevice":{"id":"dev-1"}}}`))
	})

	mux.HandleFunc("/users/uid-123/temperature", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"currentLevel":5,"currentState":{"type":"on"}}`))
			return
		}
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		// first call rate limits, second succeeds
		if r.Header.Get("X-Test-Retry") == "done" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	})

	srv := httptest.NewServer(mux)

	// client with pre-set token to skip auth
	c := New("email", "pass", "", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	return srv, c
}

func TestRequireUserFilledAutomatically(t *testing.T) {
	srv, c := mockServer(t)
	defer srv.Close()

	// UserID empty; GetStatus should fetch it from /users/me
	st, err := c.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if c.UserID != "uid-123" {
		t.Fatalf("expected user id populated, got %s", c.UserID)
	}
	if st.CurrentLevel != 5 || st.CurrentState.Type != "on" {
		t.Fatalf("unexpected status %+v", st)
	}
}

func Test429Retry(t *testing.T) {
	count := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		count++
		if count == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	start := time.Now()
	if err := c.do(context.Background(), http.MethodGet, "/ping", nil, nil, nil); err != nil {
		t.Fatalf("do retry: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 attempts, got %d", count)
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second {
		t.Fatalf("expected backoff, got %v", elapsed)
	}
}

func TestDoHandlesGzipResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/gzipped", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		json.NewEncoder(gz).Encode(map[string]string{"hello": "world"})
		gz.Close()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	var out map[string]string
	if err := c.do(context.Background(), http.MethodGet, "/gzipped", nil, nil, &out); err != nil {
		t.Fatalf("do gzip: %v", err)
	}
	if out["hello"] != "world" {
		t.Fatalf("expected {hello: world}, got %v", out)
	}
}

