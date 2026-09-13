package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHouseholdTargetsRejectInvalidUserIdentity(t *testing.T) {
	for _, id := range []string{"", "different-user"} {
		t.Run(id, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/devices/dev" {
					w.Write([]byte(`{"result":{"leftUserId":"expected-user"}}`))
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"user": map[string]string{"userId": id}})
			}))
			defer server.Close()
			c := New("fixture", "fixture", "authenticated-user", "", "")
			c.BaseURL, c.DeviceID, c.HTTP = server.URL, "dev", server.Client()
			c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
			if targets, err := c.HouseholdUserTargets(t.Context()); !errors.Is(err, ErrInvalidHouseholdUser) || targets != nil {
				t.Fatalf("targets=%v error=%v", targets, err)
			}
		})
	}
}
