package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/tokencache"
)

func TestAwayStatus(t *testing.T) {
	for _, tc := range []struct {
		name, device, side, userID, format string
		fields                             []string
		both, missingID, failRead          bool
		wantUsers, wantErr                 string
	}{
		{name: "left away collapse", device: `{"leftUserId":"uid-b","rightUserId":"uid-b","awaySides":{"leftUserId":"uid-a","rightUserId":"uid-b"}}`, wantUsers: "uid-b,uid-a"},
		{name: "right away collapse", device: `{"leftUserId":"uid-a","rightUserId":"uid-a","awaySides":{"leftUserId":"uid-a","rightUserId":"uid-b"}}`, side: "right", wantUsers: "uid-b"},
		{name: "all away filtered lookup", device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, both: true, wantUsers: "uid-a,uid-b"},
		{name: "explicit user", device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, userID: "uid-a", wantUsers: "uid-a"},
		{name: "fields", device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, fields: []string{"side", "away"}, wantUsers: "uid-a,uid-b"},
		{name: "csv", device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, format: "csv", wantUsers: "uid-a,uid-b"},
		{name: "table", device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, format: "table", wantUsers: "uid-a,uid-b"},
		{name: "empty household", device: `{}`, wantErr: "no household users found"},
		{name: "missing user ID", device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, missingID: true, wantErr: "household user is missing a user ID"},
		{name: "conflicting side", both: true, side: "left", wantErr: "--both conflicts"},
		{name: "conflicting user", both: true, userID: "uid-a", wantErr: "--both conflicts"},
		{name: "read failure", device: `{"leftUserId":"uid-a","rightUserId":"uid-b"}`, failRead: true, wantUsers: "uid-a", wantErr: "reading away for uid-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useTempKeyring(t)
			resetViper(t)
			t.Cleanup(viper.Reset)
			format := tc.format
			if format == "" {
				format = "json"
			}
			viper.Set("output", format)
			viper.Set("fields", tc.fields)
			var readUsers []string
			mux := http.NewServeMux()
			mux.HandleFunc("/devices/dev-1", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("filter") != "leftUserId,rightUserId,awaySides" {
					t.Error("household discovery omitted the side-field filter")
					w.Write([]byte(`{"result":{}}`))
					return
				}
				w.Write([]byte(`{"result":` + tc.device + `}`))
			})
			mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
				userID := strings.TrimPrefix(r.URL.Path, "/users/")
				if tc.missingID && userID == "uid-b" {
					userID = ""
				}
				json.NewEncoder(w).Encode(map[string]any{"user": map[string]any{"userId": userID, "firstName": "User", "currentDevice": map[string]string{"side": "away"}}})
			})
			mux.HandleFunc("/v1/users/", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/away-mode") {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				userID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/users/"), "/away-mode")
				readUsers = append(readUsers, userID)
				if tc.failRead {
					http.Error(w, "fixture failure", http.StatusBadRequest)
					return
				}
				json.NewEncoder(w).Encode(map[string]bool{"isAway": true})
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
			command.Flags().Bool("both", tc.both, "")
			addTargetingFlags(command, true)
			command.Flags().Set("side", tc.side)
			command.Flags().Set("target-user-id", tc.userID)
			out, err := captureAwayStatus(t, func() error { return runAwayStatusWithClient(context.Background(), command, cl) })
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || out != "" {
					t.Fatalf("output %q, error %v; want error %q without output", out, err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(readUsers, ","); got != tc.wantUsers {
				t.Fatalf("queried users = %q, want %q", got, tc.wantUsers)
			}
			if tc.wantErr != "" {
				return
			}
			if format != "json" {
				for _, field := range []string{"side", "user_id", "away", "left", "right", "true"} {
					if !strings.Contains(out, field) {
						t.Errorf("%s output missing %q: %s", format, field, out)
					}
				}
				return
			}
			var rows []map[string]any
			if err := json.Unmarshal([]byte(out), &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != len(readUsers) {
				t.Fatalf("got %d rows for %d users", len(rows), len(readUsers))
			}
			for i, row := range rows {
				wantSide := map[string]string{"uid-a": "left", "uid-b": "right"}[readUsers[i]]
				if row["side"] != wantSide || row["away"] != true {
					t.Errorf("incorrect away row: %+v", row)
				}
				if len(tc.fields) > 0 {
					if len(row) != len(tc.fields) {
						t.Errorf("unexpected fields: %+v", row)
					}
				} else if row["user_id"] != readUsers[i] {
					t.Errorf("incorrect user: %+v", row)
				}
			}
		})
	}
}

func captureAwayStatus(t *testing.T, run func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	previous := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = previous }()
	runErr := run()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), runErr
}
