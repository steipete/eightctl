package daemon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/tokencache"
)

func TestParseTemp(t *testing.T) {
	tests := map[string]int{
		"-40":  -40,
		"55F":  -100,
		"100F": 100,
		"13C":  -100,
		"38C":  100,
	}
	for input, want := range tests {
		got, err := ParseTemp(input)
		if err != nil {
			t.Fatalf("ParseTemp(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ParseTemp(%q) = %d, want %d", input, got, want)
		}
	}
	if _, err := ParseTemp("warm"); err == nil {
		t.Fatalf("expected invalid temperature error")
	}
}

func TestRunnerProcessExecutesDueItemsOnce(t *testing.T) {
	useTempKeyring(t)
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := client.New("email", "pass", "uid", "", "")
	c.AppURL = srv.URL
	c.BaseURL = srv.URL
	c.HTTP = srv.Client()
	if err := tokencache.Save(c.Identity(), "tok", time.Now().Add(time.Hour), "uid"); err != nil {
		t.Fatalf("save token: %v", err)
	}

	now := time.Date(2026, 4, 22, 7, 30, 12, 0, time.UTC)
	r := Runner{
		Items: []ScheduleItem{
			{Time: "07:30", Action: "on"},
			{Time: "07:30", Action: "off"},
			{Time: "07:30", Action: "temp", Temperature: "20"},
			{Time: "07:31", Action: "on"},
		},
		Client:   c,
		Timezone: time.UTC,
	}
	executed := map[string]bool{}
	if err := r.process(now, executed); err != nil {
		t.Fatalf("process: %v", err)
	}
	if err := r.process(now, executed); err != nil {
		t.Fatalf("process second pass: %v", err)
	}
	if got, want := strings.Join(requests, ","), strings.Join([]string{
		"PUT /v1/users/uid/temperature",
		"PUT /v1/users/uid/temperature",
		"PUT /v1/users/uid/temperature",
		"PUT /v1/users/uid/temperature",
	}, ","); got != want {
		t.Fatalf("requests = %s, want %s", got, want)
	}
}

func TestRunnerProcessUsesScheduleDate(t *testing.T) {
	pacific := time.FixedZone("PDT", -7*60*60)
	for _, tt := range []struct {
		name string
		now  time.Time
		zone *time.Location
		at   string
		key  string
	}{
		{
			name: "schedule date ahead of host",
			now:  time.Date(2026, 8, 30, 23, 5, 12, 0, pacific),
			zone: time.UTC,
			at:   "06:05",
			key:  "2026-08-31 06:05temp",
		},
		{
			name: "schedule date behind host",
			now:  time.Date(2026, 8, 31, 6, 5, 12, 0, time.UTC),
			zone: pacific,
			at:   "23:05",
			key:  "2026-08-30 23:05temp",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := Runner{
				Items:    []ScheduleItem{{Time: tt.at, Action: "temp", Temperature: "-20"}},
				Timezone: tt.zone,
				DryRun:   true,
			}
			executed := map[string]bool{}
			if err := r.process(tt.now, executed); err != nil {
				t.Fatal(err)
			}
			if !executed[tt.key] {
				t.Fatalf("due schedule was missed: executed = %v, want %s", executed, tt.key)
			}
		})
	}
}

func useTempKeyring(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	opener := func() (keyring.Keyring, error) {
		return keyring.Open(keyring.Config{
			ServiceName:      "eightctl-test",
			AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
			FileDir:          filepath.Join(tmp, "keyring"),
			FilePasswordFunc: func(_ string) (string, error) { return "test-pass", nil },
		})
	}
	restore := tokencache.SetOpenKeyringForTest(opener)
	restoreFile := tokencache.SetOpenFileKeyringForTest(opener)
	t.Cleanup(restore)
	t.Cleanup(restoreFile)
}

func TestRunnerProcessErrors(t *testing.T) {
	r := Runner{Timezone: time.UTC}
	if err := r.process(time.Now(), map[string]bool{}); err != nil {
		t.Fatalf("empty process: %v", err)
	}
	r.Items = []ScheduleItem{{Time: "bad", Action: "on"}}
	if err := r.process(time.Now(), map[string]bool{}); err == nil {
		t.Fatalf("expected bad time error")
	}
	r.Items = []ScheduleItem{{Time: "07:30", Action: "bogus"}}
	now := time.Date(2026, 4, 22, 7, 30, 0, 0, time.UTC)
	if err := r.process(now, map[string]bool{}); err == nil {
		t.Fatalf("expected unknown action error")
	}
}

func TestRunnerPIDFile(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "run", "daemon.pid")
	r := Runner{PIDFile: pidFile}
	if err := r.writePID(); err != nil {
		t.Fatalf("writePID: %v", err)
	}
	if data, err := os.ReadFile(pidFile); err != nil || strings.TrimSpace(string(data)) == "" {
		t.Fatalf("pid file = %q, err = %v", string(data), err)
	}
	if err := r.writePID(); err == nil {
		t.Fatalf("expected already running error")
	}
	r.removePID()
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatalf("pid file should be removed, stat err = %v", err)
	}
}

func TestRunnerRunStopsWhenContextCanceled(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "daemon.pid")
	r := Runner{PIDFile: pidFile}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatalf("pid file should be removed, stat err = %v", err)
	}
}

func ExampleParseTemp() {
	level, _ := ParseTemp("68F")
	fmt.Println(level)
	// Output:
	// -42
}
