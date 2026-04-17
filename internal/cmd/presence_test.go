package cmd

import "testing"

func TestPresenceCommandDefinesRangeFlags(t *testing.T) {
	if presenceCmd.Flags().Lookup("from") == nil {
		t.Fatalf("expected --from flag")
	}
	if presenceCmd.Flags().Lookup("to") == nil {
		t.Fatalf("expected --to flag")
	}
}

func TestValidatePresenceDateRange(t *testing.T) {
	if err := validatePresenceDateRange("2026-04-01", "2026-04-17"); err != nil {
		t.Fatalf("validatePresenceDateRange: %v", err)
	}
}

func TestValidatePresenceDateRangeRejectsInvertedRange(t *testing.T) {
	err := validatePresenceDateRange("2026-04-17", "2026-04-01")
	if err == nil {
		t.Fatalf("expected error")
	}
	if got, want := err.Error(), "--to must be >= --from"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}
