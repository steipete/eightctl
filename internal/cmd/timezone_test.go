package cmd

import "testing"

func TestResolveAPITimezoneExplicit(t *testing.T) {
	got, err := resolveAPITimezone("America/New_York")
	if err != nil {
		t.Fatalf("resolveAPITimezone: %v", err)
	}
	if got != "America/New_York" {
		t.Fatalf("timezone = %q, want America/New_York", got)
	}
}
