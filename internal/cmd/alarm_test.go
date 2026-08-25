package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
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

func TestVerifySmartAlarmRequiresLightSleepAndDisabledCap(t *testing.T) {
	if err := verifySmartAlarm(&client.OneOffAlarm{
		Smart: &client.AlarmSmart{
			LightSleepEnabled: true,
			SleepCapEnabled:   false,
			SleepCapMinutes:   480,
		},
	}); err != nil {
		t.Fatalf("valid Smart Alarm rejected: %v", err)
	}
	if err := verifySmartAlarm(&client.OneOffAlarm{Smart: &client.AlarmSmart{}}); err == nil {
		t.Fatal("expected missing light-sleep support to fail")
	}
	if err := verifySmartAlarm(&client.OneOffAlarm{Smart: &client.AlarmSmart{
		LightSleepEnabled: true,
		SleepCapEnabled:   true,
		SleepCapMinutes:   480,
	}}); err == nil {
		t.Fatal("expected enabled sleep cap to fail")
	}
}

func TestSmartAlarmSettingsAreExplicit(t *testing.T) {
	if smartAlarmSettings(false) != nil {
		t.Fatal("disabled Smart Alarm flag should omit Smart Alarm settings")
	}
	settings := smartAlarmSettings(true)
	if settings == nil || !settings.LightSleepEnabled || settings.SleepCapEnabled || settings.SleepCapMinutes != 480 {
		t.Fatalf("settings = %#v, want light sleep enabled with a disabled 480-minute cap", settings)
	}
}

func TestOneOffAlarmPayloadIncludesSmartSetting(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("one-off-time", "08:30")
	viper.Set("one-off-vibration-level", 50)
	viper.Set("one-off-pattern", "RISE")
	viper.Set("one-off-smart", true)

	alarm, err := oneOffAlarmFromFlags(alarmCreateOneOffCmd)
	if err != nil {
		t.Fatalf("oneOffAlarmFromFlags: %v", err)
	}
	if alarm.Smart == nil || !alarm.Smart.LightSleepEnabled || alarm.Smart.SleepCapEnabled || alarm.Smart.SleepCapMinutes != 480 {
		t.Fatalf("alarm Smart settings = %#v, want explicit Smart Alarm settings", alarm.Smart)
	}
}

func TestValidateOneOffThermalLevelRejectsOutOfRangeValues(t *testing.T) {
	if err := validateOneOffThermalLevel(true, -100); err != nil {
		t.Fatalf("minimum thermal level rejected: %v", err)
	}
	if err := validateOneOffThermalLevel(true, 101); err == nil {
		t.Fatal("out-of-range thermal level should fail even when thermal wake is disabled")
	}
}

func TestVerifyPersistedSmartAlarmRetriesTransientReadBack(t *testing.T) {
	attempts := 0
	err := verifyPersistedSmartAlarm(func() (*client.OneOffAlarm, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("alarm not visible yet")
		}
		return &client.OneOffAlarm{Smart: &client.AlarmSmart{
			LightSleepEnabled: true,
			SleepCapEnabled:   false,
			SleepCapMinutes:   480,
		}}, nil
	}, 3, 0)
	if err != nil {
		t.Fatalf("verifyPersistedSmartAlarm: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestVerifyPersistedSmartAlarmReportsExhaustedRetries(t *testing.T) {
	attempts := 0
	err := verifyPersistedSmartAlarm(func() (*client.OneOffAlarm, error) {
		attempts++
		return nil, errors.New("alarm not visible")
	}, 3, 0)
	if err == nil {
		t.Fatal("expected exhausted read-back retries to fail")
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
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
