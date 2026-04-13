package cmd

import (
	"testing"

	"github.com/steipete/eightctl/internal/client"
)

func TestTargetListSuffixSingle(t *testing.T) {
	got := targetListSuffix([]client.HouseholdUserTarget{{UserID: "u1", Side: "right"}})
	if want := " for side right"; got != want {
		t.Fatalf("suffix = %q, want %q", got, want)
	}
}

func TestTargetListSuffixMultipleSides(t *testing.T) {
	got := targetListSuffix([]client.HouseholdUserTarget{
		{UserID: "u1", Side: "left"},
		{UserID: "u2", Side: "right"},
	})
	if want := " for sides left, right"; got != want {
		t.Fatalf("suffix = %q, want %q", got, want)
	}
}

func TestTargetListSuffixMultipleUsersWithoutSides(t *testing.T) {
	got := targetListSuffix([]client.HouseholdUserTarget{
		{UserID: "u1"},
		{UserID: "u2"},
	})
	if want := " for all discovered users"; got != want {
		t.Fatalf("suffix = %q, want %q", got, want)
	}
}
