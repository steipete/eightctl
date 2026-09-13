package cmd

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestCurrentDateUsesConfiguredTimezone(t *testing.T) {
	oldLocal := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = oldLocal })
	synctest.Test(t, func(t *testing.T) {
		date, err := currentDate("America/Los_Angeles")
		if err != nil || date != "1999-12-31" {
			t.Fatalf("date=%s error=%v", date, err)
		}
		if _, err := currentDate("invalid/timezone"); err == nil {
			t.Fatal("invalid timezone accepted")
		}
	})
}

func TestResolveAPITimezoneExplicit(t *testing.T) {
	got, err := resolveAPITimezone("America/New_York")
	if err != nil {
		t.Fatalf("resolveAPITimezone: %v", err)
	}
	if got != "America/New_York" {
		t.Fatalf("timezone = %q, want America/New_York", got)
	}
}

func TestResolveAPITimezoneUsesLocalIANAWhenValueIsLocal(t *testing.T) {
	orig := localIANA
	localIANA = func() string { return "America/Los_Angeles" }
	t.Cleanup(func() { localIANA = orig })

	got, err := resolveAPITimezone("local")
	if err != nil {
		t.Fatalf("resolveAPITimezone: %v", err)
	}
	if got != "America/Los_Angeles" {
		t.Fatalf("timezone = %q, want America/Los_Angeles", got)
	}
}

func TestResolveAPITimezoneFallsBackToUTCWhenLocalIsUnknown(t *testing.T) {
	origLocal := time.Local
	time.Local = time.FixedZone("Local", 0)
	t.Cleanup(func() { time.Local = origLocal })

	origIANA := localIANA
	localIANA = func() string { return "" }
	t.Cleanup(func() { localIANA = origIANA })

	got, err := resolveAPITimezone("local")
	if err != nil {
		t.Fatalf("resolveAPITimezone: %v", err)
	}
	if got != "UTC" {
		t.Fatalf("timezone = %q, want UTC", got)
	}
}

func TestExtractZoneinfoSuffix(t *testing.T) {
	cases := map[string]string{
		"/var/db/timezone/zoneinfo/America/New_York":             "America/New_York",
		"/private/var/db/timezone/tz/2024a.1.0/zoneinfo/Etc/UTC": "Etc/UTC",
		"/usr/share/zoneinfo/Europe/Berlin":                      "Europe/Berlin",
		"no-zoneinfo-here":                                       "",
	}
	for input, want := range cases {
		if got := extractZoneinfoSuffix(input); got != want {
			t.Errorf("extractZoneinfoSuffix(%q) = %q, want %q", input, got, want)
		}
	}
}
