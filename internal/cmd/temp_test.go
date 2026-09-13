package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func parseTempCommandArgs(args []string) (value, userID, side string, help bool, err error) {
	command := &cobra.Command{Use: "temp"}
	addTargetingFlags(command, true)
	err = parseTemperatureFlags(command, args)
	value = command.Flags().Arg(0)
	userID, _ = command.Flags().GetString("target-user-id")
	side, _ = command.Flags().GetString("side")
	help, _ = command.Flags().GetBool("help")
	return
}

func TestTemperatureParsesInheritedFlags(t *testing.T) {
	root := &cobra.Command{Use: "eightctl"}
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().String("password", "", "")
	command := &cobra.Command{Use: "temp"}
	addTargetingFlags(command, true)
	root.AddCommand(command)
	if err := parseTemperatureFlags(command, []string{"-40", "--config", "settings.yaml", "--password", "-123", "--side", "right"}); err != nil {
		t.Fatal(err)
	}
	if command.Flags().Arg(0) != "-40" {
		t.Fatal("negative temperature lost")
	}
	if got, _ := command.Flags().GetString("password"); got != "-123" {
		t.Fatalf("password = %q", got)
	}
	if got, _ := command.Flags().GetString("config"); got != "settings.yaml" {
		t.Fatalf("config = %q", got)
	}
}

func TestParseTempCommandArgsAllowsNegativeLevelBeforeFlags(t *testing.T) {
	tempValue, targetUserID, side, help, err := parseTempCommandArgs([]string{"-40", "--side", "right"})
	if err != nil {
		t.Fatalf("parse args: %v", err)
	}
	if help {
		t.Fatalf("did not expect help")
	}
	if tempValue != "-40" {
		t.Fatalf("tempValue = %q, want %q", tempValue, "-40")
	}
	if side != "right" {
		t.Fatalf("side = %q, want %q", side, "right")
	}
	if targetUserID != "" {
		t.Fatalf("targetUserID = %q, want empty", targetUserID)
	}
}

func TestParseTempCommandArgsAllowsNegativeCelsiusAfterFlags(t *testing.T) {
	tempValue, targetUserID, side, help, err := parseTempCommandArgs([]string{"--target-user-id", "user-123", "-40C"})
	if err != nil {
		t.Fatalf("parse args: %v", err)
	}
	if help {
		t.Fatalf("did not expect help")
	}
	if tempValue != "-40C" {
		t.Fatalf("tempValue = %q, want %q", tempValue, "-40C")
	}
	if side != "" {
		t.Fatalf("side = %q, want empty", side)
	}
	if targetUserID != "user-123" {
		t.Fatalf("targetUserID = %q, want %q", targetUserID, "user-123")
	}
}

func TestParseTempCommandArgsRejectsUnknownFlag(t *testing.T) {
	_, _, _, _, err := parseTempCommandArgs([]string{"--bogus", "-40"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got, want := err.Error(), "unknown flag: --bogus"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestParseTempCommandArgsRejectsMissingTemperature(t *testing.T) {
	_, _, _, _, err := parseTempCommandArgs([]string{"--side", "left"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got, want := err.Error(), "requires exactly 1 temperature value"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestParseTempCommandArgsHelp(t *testing.T) {
	_, _, _, help, err := parseTempCommandArgs([]string{"--help"})
	if err != nil {
		t.Fatalf("parse args: %v", err)
	}
	if !help {
		t.Fatalf("expected help")
	}
}
