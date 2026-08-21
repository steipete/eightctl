package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type recordedRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   string
}

func newRecordingClient(t *testing.T) (*Client, *[]recordedRequest, func()) {
	t.Helper()
	records := []recordedRequest{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		records = append(records, recordedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.Query(),
			Body:   string(body),
		})
		w.Header().Set("Content-Type", "application/json")
		writeActionResponse(t, w, r)
	})
	srv := httptest.NewServer(mux)

	oldAppAPIBaseURL := appAPIBaseURL
	appAPIBaseURL = srv.URL

	c := New("email", "pass", "uid", "", "")
	c.DeviceID = "dev"
	c.BaseURL = srv.URL
	c.AppURL = srv.URL
	c.token = "tok"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	cleanup := func() {
		appAPIBaseURL = oldAppAPIBaseURL
		srv.Close()
	}
	return c, &records, cleanup
}

func writeActionResponse(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	switch {
	case r.URL.Path == "/users/uid/alarms" && r.Method == http.MethodGet:
		io.WriteString(w, `{"alarms":[{"id":"alarm-1","time":"07:00","enabled":true,"daysOfWeek":[1],"vibration":true}]}`)
	case r.URL.Path == "/v1/users/uid/alarms" && r.Method == http.MethodPost:
		io.WriteString(w, `{"alarm":{"id":"one-off-alarm","time":"08:30:00","enabled":true,"vibration":{"enabled":true,"powerLevel":50,"pattern":"RISE"},"thermal":{"enabled":true,"level":-10}}}`)
	case strings.HasPrefix(r.URL.Path, "/users/uid/alarms") && (r.Method == http.MethodPost || r.Method == http.MethodPatch):
		io.WriteString(w, `{"alarm":{"id":"alarm-1","time":"07:00","enabled":true}}`)
	case r.URL.Path == "/users/uid/audio/tracks" || r.URL.Path == "/audio/tracks":
		io.WriteString(w, `{"tracks":[{"id":"track-1","title":"Rain","type":"sound"}]}`)
	case r.URL.Path == "/users/uid/temperature":
		io.WriteString(w, `{"smart":{"enabled":true}}`)
	case r.URL.Path == "/v1/users/uid/temperature":
		io.WriteString(w, `{"currentLevel":12,"currentState":{"type":"smart"}}`)
	case r.URL.Path == "/users/uid/trends":
		io.WriteString(w, `{"days":[{"day":"2026-04-22","score":88}]}`)
	default:
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

type actionEndpointTestCase struct {
	name      string
	call      func(context.Context, *Client) error
	want      recordedRequest
	wantQuery map[string]string
	bodyHas   string
}

func assertActionEndpoints(t *testing.T, tests []actionEndpointTestCase) {
	t.Helper()
	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, records, cleanup := newRecordingClient(t)
			defer cleanup()
			if err := tt.call(ctx, c); err != nil {
				t.Fatalf("call: %v", err)
			}
			if len(*records) == 0 {
				t.Fatalf("no requests recorded")
			}
			got := (*records)[len(*records)-1]
			if got.Method != tt.want.Method || got.Path != tt.want.Path {
				t.Fatalf("request = %s %s, want %s %s", got.Method, got.Path, tt.want.Method, tt.want.Path)
			}
			for key, want := range tt.wantQuery {
				if got.Query.Get(key) != want {
					t.Fatalf("query %s = %q, want %q; full query %s", key, got.Query.Get(key), want, got.Query.Encode())
				}
			}
			if tt.bodyHas != "" && !strings.Contains(got.Body, tt.bodyHas) {
				t.Fatalf("body = %q, want substring %q", got.Body, tt.bodyHas)
			}
		})
	}
}
