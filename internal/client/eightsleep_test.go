package client

import (
	"context"
	"encoding/json"
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

func TestAuthTokenEndpoint_FormEncoded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected form-urlencoded, got %s", ct)
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if got := r.PostFormValue("client_id"); got != defaultClientID {
			t.Errorf("client_id = %q, want %q", got, defaultClientID)
		}
		if got := r.PostFormValue("client_secret"); got != defaultClientSecret {
			t.Errorf("client_secret = %q, want %q", got, defaultClientSecret)
		}
		if got := r.PostFormValue("grant_type"); got != "password" {
			t.Errorf("grant_type = %q, want password", got)
		}
		if got := r.PostFormValue("username"); got != "test@example.com" {
			t.Errorf("username = %q, want test@example.com", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-123",
			"expires_in":   3600,
			"userId":       "uid-abc",
		})
	}))
	defer srv.Close()

	old := authURL
	authURL = srv.URL
	defer func() { authURL = old }()

	c := New("test@example.com", "secret", "", "", "")
	c.HTTP = srv.Client()

	if err := c.Authenticate(context.Background()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if c.token != "tok-123" {
		t.Errorf("token = %q, want tok-123", c.token)
	}
	if c.UserID != "uid-abc" {
		t.Errorf("UserID = %q, want uid-abc", c.UserID)
	}
}

func TestAuthTokenEndpoint_ReturnsErrorOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	}))
	defer srv.Close()

	old := authURL
	authURL = srv.URL
	defer func() { authURL = old }()

	c := New("test@example.com", "secret", "", "", "")
	c.HTTP = srv.Client()

	if err := c.Authenticate(context.Background()); err == nil {
		t.Fatal("Authenticate: expected error, got nil")
	}
}

func TestNoExplicitGzipHeader(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		ae := r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"accept_encoding": ae})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("e", "p", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	var out map[string]string
	if err := c.do(context.Background(), http.MethodGet, "/check", nil, nil, &out); err != nil {
		t.Fatalf("do: %v", err)
	}
	if out["accept_encoding"] == "" {
		t.Fatal("expected Accept-Encoding to be set by Go's transport")
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

func TestSetAwayMode(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any

	mux := http.NewServeMux()
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-123","currentDevice":{"id":"dev-1"}}}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	old := appAPIBaseURL
	appAPIBaseURL = srv.URL
	defer func() { appAPIBaseURL = old }()

	c := New("e", "p", "uid-123", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	// Test activate
	if err := c.SetAwayMode(context.Background(), "", true); err != nil {
		t.Fatalf("SetAwayMode on: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/users/uid-123/away-mode" {
		t.Errorf("path = %q, want /users/uid-123/away-mode", gotPath)
	}
	period, ok := gotBody["awayPeriod"].(map[string]any)
	if !ok {
		t.Fatal("missing awayPeriod in body")
	}
	if _, ok := period["start"]; !ok {
		t.Error("activate should send awayPeriod.start")
	}

	// Test deactivate
	if err := c.SetAwayMode(context.Background(), "uid-456", false); err != nil {
		t.Fatalf("SetAwayMode off: %v", err)
	}
	if gotPath != "/users/uid-456/away-mode" {
		t.Errorf("path = %q, want /users/uid-456/away-mode", gotPath)
	}
	period, ok = gotBody["awayPeriod"].(map[string]any)
	if !ok {
		t.Fatal("missing awayPeriod in body")
	}
	if _, ok := period["end"]; !ok {
		t.Error("deactivate should send awayPeriod.end")
	}
}

func TestDeviceSides(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-123","currentDevice":{"id":"dev-1"}}}`))
	})
	mux.HandleFunc("/devices/dev-1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":{"leftUserId":"uid-left","rightUserId":"uid-right"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("e", "p", "", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	sides, err := c.Device().Sides(context.Background())
	if err != nil {
		t.Fatalf("Sides: %v", err)
	}
	if sides.LeftUserID != "uid-left" {
		t.Errorf("LeftUserID = %q, want uid-left", sides.LeftUserID)
	}
	if sides.RightUserID != "uid-right" {
		t.Errorf("RightUserID = %q, want uid-right", sides.RightUserID)
	}
}

func Test429RetryCapped(t *testing.T) {
	count := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/always429", func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(http.StatusTooManyRequests)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	err := c.do(context.Background(), http.MethodGet, "/always429", nil, nil, nil)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if count != maxRetries+1 {
		t.Fatalf("expected %d attempts, got %d", maxRetries+1, count)
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
			if err := req.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			if got := req.PostFormValue("client_id"); got != defaultClientID {
				t.Fatalf("client_id = %q, want %q", got, defaultClientID)
			}
			if got := req.PostFormValue("client_secret"); got != defaultClientSecret {
				t.Fatalf("client_secret = %q, want %q", got, defaultClientSecret)
			}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"tok","expires_in":3600,"userId":"uid-123"}`)),
				Header:     make(http.Header),
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
