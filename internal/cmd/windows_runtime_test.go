//go:build windows

package cmd

import (
	"os"
	"testing"
	"time"
)

func TestWindowsSystemTimezone(t *testing.T) {
	if os.Getenv("EIGHTCTL_WINDOWS_PROOF") != "1" {
		t.Skip("requires the disposable CI runner set to Pacific Standard Time")
	}
	t.Setenv("TZ", "")
	zone, err := resolveAPITimezone("")
	if err != nil || zone != "America/Los_Angeles" {
		t.Fatalf("system timezone = %q, %v; want America/Los_Angeles", zone, err)
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Date(2026, 11, 6, 1, 0, 0, 0, time.UTC).In(loc).Format(time.DateOnly); got != "2026-11-05" {
		t.Fatalf("local date = %s", got)
	}
	if got, err := resolveAPITimezone("Europe/Vienna"); err != nil || got != "Europe/Vienna" {
		t.Fatalf("explicit override = %q, %v", got, err)
	}
	t.Log("actual Windows registry resolved Pacific Standard Time to America/Los_Angeles; UTC-boundary date and explicit override preserved")
}
