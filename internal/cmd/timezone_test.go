package cmd

import (
	"testing"
	"time"
)

func TestResolveAPITimezoneExplicit(t *testing.T) {
	got, err := resolveAPITimezone("America/New_York")
	if err != nil {
		t.Fatalf("resolveAPITimezone: %v", err)
	}
	if got != "America/New_York" {
		t.Fatalf("timezone = %q, want America/New_York", got)
	}
}

func TestResolveAPITimezoneFallsBackToUTCWhenLocalIsUnknown(t *testing.T) {
	original := time.Local
	time.Local = time.FixedZone("Local", 0)
	t.Cleanup(func() { time.Local = original })

	got, err := resolveAPITimezone("local")
	if err != nil {
		t.Fatalf("resolveAPITimezone: %v", err)
	}
	if got != "UTC" {
		t.Fatalf("timezone = %q, want UTC", got)
	}
}
