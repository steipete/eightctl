package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// mockServer builds a test server that can serve a handful of endpoints the client expects.
func mockServer(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-123","devices":["dev-1"],"currentDevice":{"id":"dev-1"}}}`))
	})

	mux.HandleFunc("/v1/users/uid-123/temperature", func(w http.ResponseWriter, r *http.Request) {
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
	c.AppURL = srv.URL
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

func Test429StopsAfterRetryLimit(t *testing.T) {
	count := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"limit exceeded"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	start := time.Now()
	err := c.do(context.Background(), http.MethodGet, "/ping", nil, nil, nil)
	if err == nil {
		t.Fatalf("expected rate limit error")
	}
	if !strings.Contains(err.Error(), "rate limited after retries") {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != maxRateLimitRetries+1 {
		t.Fatalf("expected %d attempts, got %d", maxRateLimitRetries+1, count)
	}
	if elapsed := time.Since(start); elapsed < time.Duration(maxRateLimitRetries)*defaultRetryDelay {
		t.Fatalf("expected retry delays, got %v", elapsed)
	}
}

func TestUnauthorizedStopsAfterReauthRetryLimit(t *testing.T) {
	count := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"bad token"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == srv.URL+"/ping" {
				return srv.Client().Transport.RoundTrip(req)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"tok","expires_in":3600,"userId":"uid"}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	err := c.do(context.Background(), http.MethodGet, "/ping", nil, nil, nil)
	if err == nil {
		t.Fatalf("expected unauthorized error")
	}
	if !strings.Contains(err.Error(), "unauthorized after re-auth retry") {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != maxUnauthorizedRetries+1 {
		t.Fatalf("expected %d attempts, got %d", maxUnauthorizedRetries+1, count)
	}
}

func TestAuthTokenEndpointUsesClientCredentials(t *testing.T) {
	c := New("user@example.com", "pass-123", "", "", "")
	c.HTTP = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", req.Method)
			}
			if got := req.URL.String(); got != authURL {
				t.Fatalf("url = %s, want %s", got, authURL)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			payload := string(body)
			if !strings.Contains(payload, `"client_id":"`+defaultClientID+`"`) {
				t.Fatalf("payload missing default client_id: %s", payload)
			}
			if !strings.Contains(payload, `"client_secret":"`+defaultClientSecret+`"`) {
				t.Fatalf("payload missing default client_secret: %s", payload)
			}
			if strings.Contains(payload, `"client_id":"sleep-client"`) {
				t.Fatalf("payload still contains legacy client_id: %s", payload)
			}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(
					`{"access_token":"tok","expires_in":3600,"userId":"uid-123"}`,
				)),
				Header: make(http.Header),
			}
			return resp, nil
		}),
	}

	if err := c.authTokenEndpoint(context.Background()); err != nil {
		t.Fatalf("authTokenEndpoint: %v", err)
	}
	if c.token != "tok" {
		t.Fatalf("token = %q, want tok", c.token)
	}
	if c.UserID != "uid-123" {
		t.Fatalf("user id = %q, want uid-123", c.UserID)
	}
}

func TestDoHandlesGzipJSONResponse(t *testing.T) {
	var payload bytes.Buffer
	gz := gzip.NewWriter(&payload)
	if _, err := gz.Write([]byte(`{"currentLevel":7,"currentState":{"type":"cooling"}}`)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/uid-123/temperature", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload.Bytes())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "uid-123", "", "")
	c.BaseURL = srv.URL
	c.AppURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	st, err := c.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if st.CurrentLevel != 7 || st.CurrentState.Type != "cooling" {
		t.Fatalf("unexpected status %+v", st)
	}
}

func TestSetTemperatureForUserUsesExplicitUserID(t *testing.T) {
	var gotPaths []string
	var gotBodies []string

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/other-user/temperature", func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		gotBodies = append(gotBodies, string(body))
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "auth-user", "", "")
	c.BaseURL = srv.URL
	c.AppURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	if err := c.SetTemperatureForUser(context.Background(), "other-user", 12); err != nil {
		t.Fatalf("SetTemperatureForUser: %v", err)
	}
	if len(gotPaths) != 2 {
		t.Fatalf("expected 2 app requests, got %d", len(gotPaths))
	}
	if gotPaths[0] != "/v1/users/other-user/temperature" || gotPaths[1] != "/v1/users/other-user/temperature" {
		t.Fatalf("paths = %#v, want both /v1/users/other-user/temperature", gotPaths)
	}
	if gotBodies[0] != `{"currentState":{"type":"smart"}}` {
		t.Fatalf("first body = %q, want smart currentState payload", gotBodies[0])
	}
	if gotBodies[1] != `{"currentLevel":12}` {
		t.Fatalf("second body = %q, want {\"currentLevel\":12}", gotBodies[1])
	}
}

func TestTurnOnForUserUsesSmartCurrentState(t *testing.T) {
	var gotBody string

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/other-user/temperature", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		gotBody = string(body)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "auth-user", "", "")
	c.BaseURL = srv.URL
	c.AppURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	if err := c.TurnOnForUser(context.Background(), "other-user"); err != nil {
		t.Fatalf("TurnOnForUser: %v", err)
	}
	if gotBody != `{"currentState":{"type":"smart"}}` {
		t.Fatalf("body = %q, want smart currentState payload", gotBody)
	}
}
