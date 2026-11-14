package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/tokencache"
)

func TestAlarmListTransportRendering(t *testing.T) {
	useTempKeyring(t)
	resetViper(t)
	defer viper.Reset()
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/users/fixture/alarms" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"alarms":[{"id":"a1","sound":"rain"},{"id":"a2"}]}`))
	}))
	defer srv.Close()
	c := client.New("fixture@example.invalid", "fixture", "fixture", "fixture-client", "fixture-secret")
	c.BaseURL = srv.URL
	c.HTTP = srv.Client()
	if err := tokencache.Save(c.Identity(), "fixture-token", time.Now().Add(time.Hour), "fixture"); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"table", "csv", "json"} {
		t.Run(format, func(t *testing.T) {
			viper.Set("output", format)
			viper.Set("fields", []string{"id", "sound"})
			out, err := captureAwayStatus(t, func() error { return runAlarmListWithClient(context.Background(), c) })
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out, "rain") || strings.Contains(out, "0x") || strings.Contains(out, "<nil>") {
				t.Fatalf("sound was not rendered: %q", out)
			}
			if format == "json" {
				var rows []map[string]any
				if err := json.Unmarshal([]byte(out), &rows); err != nil {
					t.Fatal(err)
				}
				if rows[0]["sound"] != "rain" || rows[1]["sound"] != nil {
					t.Fatalf("JSON contract changed: %s", out)
				}
			}
			t.Logf("%s: %s", format, out)
		})
	}
	if requests != 3 {
		t.Fatalf("requests=%d", requests)
	}
}
