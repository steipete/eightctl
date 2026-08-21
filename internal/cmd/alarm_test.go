package cmd

import (
	"testing"

	"github.com/spf13/viper"
)

func TestNormalizeAlarmTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "hours and minutes", input: "08:30", want: "08:30:00"},
		{name: "seconds", input: "08:30:15", want: "08:30:15"},
		{name: "invalid", input: "tomorrow", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeAlarmTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeAlarmTime(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("normalizeAlarmTime(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeOneOffPattern(t *testing.T) {
	if got, err := normalizeOneOffPattern("RISE"); err != nil || got != "RISE" {
		t.Fatalf("RISE = %q, %v", got, err)
	}
	if got, err := normalizeOneOffPattern("INTENSE"); err != nil || got != "intense" {
		t.Fatalf("INTENSE = %q, %v", got, err)
	}
	if _, err := normalizeOneOffPattern("unknown"); err == nil {
		t.Fatal("expected unknown pattern to fail")
	}
}

func TestOneOffThermalLevelProvidedFromConfig(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("one-off-thermal-level", -10)

	if !oneOffThermalLevelProvided(alarmCreateOneOffCmd) {
		t.Fatal("expected configured thermal level to enable thermal wake")
	}
}

func TestOneOffThermalLevelNotProvidedByDefault(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	if err := viper.BindPFlag("one-off-thermal-level", alarmCreateOneOffCmd.Flags().Lookup("thermal-level")); err != nil {
		t.Fatalf("bind thermal level: %v", err)
	}

	if oneOffThermalLevelProvided(alarmCreateOneOffCmd) {
		t.Fatal("did not expect the default thermal level to enable thermal wake")
	}
}
