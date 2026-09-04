package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/tokencache"
)

type awayRoundTripper func(*http.Request) (*http.Response, error)

func (f awayRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAwayBoth(t *testing.T) {
	for _, tc := range []struct {
		name      string
		on        bool
		device    string
		missingID bool
		failWrite bool
		wantUsers string
		wantErr   string
	}{
		{name: "all away resumes both", device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, wantUsers: "uid-a,uid-b"},
		{name: "activates both", on: true, device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, wantUsers: "uid-a,uid-b"},
		{name: "solo writes once", device: `{"leftUserId":"uid-a","rightUserId":"uid-a"}`, wantUsers: "uid-a"},
		{name: "empty household fails", device: `{}`, wantErr: "no household users found"},
		{name: "missing user ID fails before writes", device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, missingID: true, wantErr: "household user is missing a user ID"},
		{name: "write failure is returned", device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, failWrite: true, wantUsers: "uid-a,uid-b", wantErr: "setting away for uid-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useTempKeyring(t)
			resetViper(t)
			t.Cleanup(viper.Reset)
			viper.Set("quiet", true)
			var users []string
			mux := http.NewServeMux()
			mux.HandleFunc("/devices/dev-1", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				// The unfiltered response loses all user IDs when everyone is away.
				if r.URL.Query().Get("filter") != "leftUserId,rightUserId,awaySides" {
					w.Write([]byte(`{"result":{"deviceId":"dev-1"}}`))
					return
				}
				w.Write([]byte(`{"result":` + tc.device + `}`))
			})
			mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
				userID := strings.TrimPrefix(r.URL.Path, "/users/")
				if tc.missingID && userID == "uid-b" {
					w.Write([]byte(`{"user":{}}`))
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"user": map[string]string{"userId": userID}})
			})
			mux.HandleFunc("/v1/users/", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/away-mode") {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				userID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/users/"), "/away-mode")
				var body struct {
					AwayPeriod map[string]string `json:"awayPeriod"`
				}
				field := "end"
				if tc.on {
					field = "start"
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.AwayPeriod) != 1 || body.AwayPeriod[field] == "" {
					t.Errorf("incorrect away payload: %+v, error %v", body, err)
				}
				users = append(users, userID)
				if tc.failWrite && userID == "uid-b" {
					http.Error(w, "write failed", http.StatusBadRequest)
					return
				}
				w.Write([]byte(`{}`))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			cl := client.New("fixture@example.invalid", "fixture", "uid-a", "fixture-client", "fixture-secret")
			cl.BaseURL, cl.DeviceID = srv.URL, "dev-1"
			if err := tokencache.Save(cl.Identity(), "fixture-token", time.Now().Add(time.Hour), "uid-a"); err != nil {
				t.Fatal(err)
			}
			transport := srv.Client().Transport
			cl.HTTP = &http.Client{Transport: awayRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "app-api.8slp.net" {
					r = r.Clone(r.Context())
					r.URL.Scheme = "http"
					r.URL.Host = strings.TrimPrefix(srv.URL, "http://")
				}
				return transport.RoundTrip(r)
			})}
			command := &cobra.Command{}
			command.Flags().Bool("both", true, "")
			addTargetingFlags(command, true)
			err := runAwayWithClient(context.Background(), command, cl, tc.on)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
			if got := strings.Join(users, ","); got != tc.wantUsers {
				t.Fatalf("written users = %q, want %q", got, tc.wantUsers)
			}
		})
	}
}
