package cmd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

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
	if alarm.Thermal.Enabled || alarm.Thermal.Level != 0 {
		t.Fatalf("Smart-only alarm must leave thermal wake disabled, got %#v", alarm.Thermal)
	}
}

// Fresh processes exercise the real CLI bindings without sharing Cobra/Viper state.
// RunE is replaced before execution so no authentication or provider call occurs.
func TestOneOffAlarmThermalOptIn(t *testing.T) {
	cases := map[string]struct {
		flags       []string
		config      string
		wantEnabled bool
		wantLevel   int
		wantSmart   bool
		wantErr     bool
	}{
		"plain":                     {},
		"smart only":                {flags: []string{"--smart"}, wantSmart: true},
		"smart neutral":             {flags: []string{"--smart", "--thermal-level=0"}, wantEnabled: true, wantSmart: true},
		"smart cold":                {flags: []string{"--smart", "--thermal-level=-100"}, wantEnabled: true, wantLevel: -100, wantSmart: true},
		"smart hot":                 {flags: []string{"--smart", "--thermal-level=100"}, wantEnabled: true, wantLevel: 100, wantSmart: true},
		"plain explicit":            {flags: []string{"--thermal-level=-10"}, wantEnabled: true, wantLevel: -10},
		"smart disabled":            {flags: []string{"--smart", "--no-thermal"}, wantSmart: true},
		"disable overrides level":   {flags: []string{"--smart", "--thermal-level=-100", "--no-thermal"}, wantLevel: -100, wantSmart: true},
		"configured level":          {flags: []string{"--smart"}, config: "one-off-thermal-level: 10\n", wantEnabled: true, wantLevel: 10, wantSmart: true},
		"configured neutral":        {flags: []string{"--smart"}, config: "one-off-thermal-level: 0\n", wantEnabled: true, wantSmart: true},
		"disable overrides config":  {flags: []string{"--smart", "--no-thermal"}, config: "one-off-thermal-level: 10\n", wantLevel: 10, wantSmart: true},
		"flag overrides config":     {flags: []string{"--smart", "--thermal-level=-20"}, config: "one-off-thermal-level: 10\n", wantEnabled: true, wantLevel: -20, wantSmart: true},
		"invalid config text":       {flags: []string{"--smart"}, config: "one-off-thermal-level: bogus\n", wantErr: true},
		"invalid config fraction":   {flags: []string{"--smart"}, config: "one-off-thermal-level: 10.5\n", wantErr: true},
		"invalid config boolean":    {flags: []string{"--smart"}, config: "one-off-thermal-level: true\n", wantErr: true},
		"invalid config disabled":   {flags: []string{"--smart", "--no-thermal"}, config: "one-off-thermal-level: bogus\n", wantErr: true},
		"invalid cold":              {flags: []string{"--smart", "--thermal-level=-101"}, wantErr: true},
		"invalid hot even disabled": {flags: []string{"--smart", "--thermal-level=101", "--no-thermal"}, wantErr: true},
	}
	if name := os.Getenv("EIGHTCTL_TEST_ONE_OFF_CASE"); name != "" {
		tc := cases[name]
		configPath := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(configPath, []byte(tc.config), 0o600); err != nil {
			t.Fatal(err)
		}
		alarmCreateOneOffCmd.RunE = func(cmd *cobra.Command, args []string) error {
			alarm, err := oneOffAlarmFromFlags(cmd)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected invalid thermal level to fail")
				}
				return nil
			}
			if err != nil {
				t.Fatal(err)
			}
			if alarm.Thermal.Enabled != tc.wantEnabled || alarm.Thermal.Level != tc.wantLevel {
				t.Fatalf("thermal = %#v, want enabled %v, level %d", alarm.Thermal, tc.wantEnabled, tc.wantLevel)
			}
			if (alarm.Smart != nil) != tc.wantSmart {
				t.Fatalf("smart = %#v, want enabled %v", alarm.Smart, tc.wantSmart)
			}
			if tc.wantSmart {
				if err := verifySmartAlarm(&alarm); err != nil {
					t.Fatal(err)
				}
			}
			return nil
		}
		args := append([]string{"alarm", "create-one-off", "--time=08:30", "--config", configPath, "--quiet"}, tc.flags...)
		rootCmd.SetArgs(args)
		if err := rootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
		return
	}
	for name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			command := exec.Command(os.Args[0], "-test.run=^TestOneOffAlarmThermalOptIn$")
			for _, variable := range os.Environ() {
				if !strings.HasPrefix(variable, "EIGHTCTL_") {
					command.Env = append(command.Env, variable)
				}
			}
			command.Env = append(command.Env, "EIGHTCTL_TEST_ONE_OFF_CASE="+name)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("one-off thermal flags: %v\n%s", err, out)
			}
		})
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
