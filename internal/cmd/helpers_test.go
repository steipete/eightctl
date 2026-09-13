package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/daemon"
)

func TestParseDays(t *testing.T) {
	for _, command := range []*cobra.Command{alarmCreateCmd, alarmUpdateCmd} {
		t.Run(command.Name(), func(t *testing.T) {
			flag := command.Flags().Lookup("days")
			previous, changed := flag.Value.String(), flag.Changed
			t.Cleanup(func() {
				_ = flag.Value.(pflag.SliceValue).Replace(nil)
				if previous != "[]" {
					_ = flag.Value.Set(strings.Trim(previous, "[]"))
				}
				flag.Changed = changed
			})
			if err := command.ParseFlags([]string{"--days", "1,2,6"}); err != nil {
				t.Fatal(err)
			}
			got, err := command.Flags().GetIntSlice("days")
			if err != nil || !reflect.DeepEqual(got, []int{1, 2, 6}) {
				t.Fatalf("days = %#v, error = %v", got, err)
			}
			if err := command.ParseFlags([]string{"--days", "x"}); err == nil {
				t.Fatal("expected invalid day error")
			}
		})
	}
}

func TestParseSchedule(t *testing.T) {
	got, err := parseSchedule([]byte("schedule:\n  - time: \"07:30\"\n    action: temp\n    temperature: 68F\n"))
	if err != nil {
		t.Fatalf("parseSchedule: %v", err)
	}
	want := []daemon.ScheduleItem{{Time: "07:30", Action: "temp", Temperature: "68F"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schedule = %#v, want %#v", got, want)
	}
	if _, err := parseSchedule([]byte("schedule: []")); err == nil {
		t.Fatalf("expected empty schedule error")
	}
	if _, err := parseSchedule([]byte("schedule: [")); err == nil {
		t.Fatalf("expected yaml error")
	}
}

func TestReadConfigSchedule(t *testing.T) {
	resetViper(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("schedule: []"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	viper.SetConfigFile(path)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}
	got, err := readConfigSchedule()
	if err != nil {
		t.Fatalf("readConfigSchedule: %v", err)
	}
	if string(got) != "schedule: []" {
		t.Fatalf("config data = %q", got)
	}
}

func TestDaemonConfigFlagUsesLoadedFile(t *testing.T) {
	resetViper(t)
	path := filepath.Join(t.TempDir(), "daemon.yaml")
	data := strings.Join([]string{
		"email: test@example.com",
		"password: test-password",
		"schedule:",
		"  - time: \"07:30\"",
		"    action: temp",
		"    temperature: -20",
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configFlag := rootCmd.PersistentFlags().Lookup("config")
	originalValue := configFlag.Value.String()
	originalChanged := configFlag.Changed
	t.Cleanup(func() {
		_ = configFlag.Value.Set(originalValue)
		configFlag.Changed = originalChanged
		viper.Reset()
	})
	if err := configFlag.Value.Set(path); err != nil {
		t.Fatalf("set --config: %v", err)
	}
	configFlag.Changed = true
	if err := viper.BindPFlag("config", configFlag); err != nil {
		t.Fatalf("bind --config: %v", err)
	}

	if err := initConfig(); err != nil {
		t.Fatal(err)
	}
	if got := viper.ConfigFileUsed(); got != path {
		t.Fatalf("ConfigFileUsed = %q, want %q", got, path)
	}
	loaded, err := readConfigSchedule()
	if err != nil {
		t.Fatalf("readConfigSchedule: %v", err)
	}
	items, err := parseSchedule(loaded)
	if err != nil {
		t.Fatalf("parseSchedule: %v", err)
	}
	want := []daemon.ScheduleItem{{Time: "07:30", Action: "temp", Temperature: "-20"}}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("schedule = %#v, want %#v", items, want)
	}
}

func TestDefaultPIDFile(t *testing.T) {
	if got := defaultPIDFile("/tmp/custom.pid"); got != "/tmp/custom.pid" {
		t.Fatalf("defaultPIDFile explicit = %q", got)
	}
	got := defaultPIDFile("")
	if !strings.HasSuffix(got, filepath.Join(".config", "eightctl", "daemon.pid")) {
		t.Fatalf("defaultPIDFile = %q", got)
	}
}

func TestMapKeysAndCurrentDate(t *testing.T) {
	if got := mapKeys(map[string]any{"b": 2, "a": 1}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("mapKeys = %#v", got)
	}
	if got, err := currentDate("UTC"); err != nil || len(got) != len("2006-01-02") {
		t.Fatalf("currentDate = %q, error = %v", got, err)
	}
}

func TestMoreTempArgBranches(t *testing.T) {
	tests := [][]string{
		{"--side"},
		{"--target-user-id"},
		{"--", "1", "2"},
		{"1", "2"},
	}
	for _, args := range tests {
		if _, _, _, _, err := parseTempCommandArgs(args); err == nil {
			t.Fatalf("parseTempCommandArgs(%v): expected error", args)
		}
	}
	if !isNegativeTempCandidate("-.5") {
		t.Fatalf("-.5 should be a negative temp candidate")
	}
	if isNegativeTempCandidate("-x") {
		t.Fatalf("-x should not be a negative temp candidate")
	}
}
