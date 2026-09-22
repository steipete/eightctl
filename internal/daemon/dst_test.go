package daemon

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestRunnerSpringForwardDoesNotRunMissingTime(t *testing.T) {
	zone, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	r := Runner{
		Items:    []ScheduleItem{{Time: "02:30", Action: "on"}},
		Timezone: zone,
		DryRun:   true,
	}
	executed := map[string]bool{}
	// The clock jumps from 01:59 to 03:00; 02:30 never occurs.
	for _, hour := range []int{1, 3} {
		now := time.Date(2026, time.March, 8, hour, 30, 12, 0, zone)
		if err := processAt(&r, now, executed); err != nil {
			t.Fatal(err)
		}
	}
	if len(executed) != 0 {
		t.Fatalf("nonexistent 02:30 schedule ran at another time: %v", executed)
	}
}

func TestRunnerFallBackRunsRepeatedTimeOnce(t *testing.T) {
	zone, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	first := time.Date(2026, time.November, 1, 5, 30, 12, 0, time.UTC)
	second := first.Add(time.Hour)
	for _, ticks := range [][]time.Time{{first, second}, {second}} {
		r := Runner{
			Items:    []ScheduleItem{{Time: "01:30", Action: "on"}},
			Timezone: zone,
			DryRun:   true,
		}
		output, err := os.CreateTemp(t.TempDir(), "dry-run")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = output.Close() })
		original := os.Stdout
		os.Stdout = output
		t.Cleanup(func() { os.Stdout = original })
		executed := map[string]bool{}
		for _, now := range ticks {
			if err := processAt(&r, now, executed); err != nil {
				t.Fatal(err)
			}
		}
		os.Stdout = original
		data, err := os.ReadFile(output.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), "DRY-RUN") != 1 {
			t.Fatalf("expected one action, got %q", data)
		}
		if len(executed) != 1 || !executed["2026-11-01 01:30on"] {
			t.Fatalf("ticks %v: expected one 01:30 action, got %v", ticks, executed)
		}
	}
}
