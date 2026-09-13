package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestCommandFlagOwnership(t *testing.T) {
	cases := map[string]struct {
		command *cobra.Command
		args    []string
		want    map[string]string
	}{
		"alarm create":         {alarmCreateCmd, []string{"alarm", "create", "--time", "07:30", "--days", "1,2", "--no-vibration", "--sound", "rain"}, map[string]string{"time": "07:30", "days": "[1 2]", "no-vibration": "true", "sound": "rain"}},
		"alarm update":         {alarmUpdateCmd, []string{"alarm", "update", "id", "--enabled=false"}, map[string]string{"enabled": "false"}},
		"audio play":           {audioPlayCmd, []string{"audio", "play", "--track", "rain"}, map[string]string{"track": "rain"}},
		"audio add":            {audioFavAddCmd, []string{"audio", "favorites", "add", "--track", "rain"}, map[string]string{"track": "rain"}},
		"audio remove":         {audioFavRemoveCmd, []string{"audio", "favorites", "remove", "--track", "rain"}, map[string]string{"track": "rain"}},
		"autopilot level":      {autopilotLevelCmd, []string{"autopilot", "level-suggestions", "--enabled=false"}, map[string]string{"enabled": "false"}},
		"autopilot snore":      {autopilotSnoreCmd, []string{"autopilot", "snore-mitigation", "--enabled=false"}, map[string]string{"enabled": "false"}},
		"config fallback":      {alarmCreateCmd, []string{"alarm", "create"}, map[string]string{"time": "08:00"}},
		"environment fallback": {alarmCreateCmd, []string{"alarm", "create"}, map[string]string{"time": "09:00"}},
	}
	if name := os.Getenv("EIGHTCTL_TEST_FLAG_CASE"); name != "" {
		tc := cases[name]
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte("time: '08:00'\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		tc.command.RunE = func(cmd *cobra.Command, args []string) error {
			for key, want := range tc.want {
				if got := fmt.Sprint(viper.Get(key)); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			return nil
		}
		rootCmd.SetArgs(append(tc.args, "--config", path, "--quiet"))
		if err := rootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
		return
	}
	// Fresh processes preserve real init-time bindings and isolate Cobra/Viper globals.
	for name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			command := exec.Command(os.Args[0], "-test.run=^TestCommandFlagOwnership$")
			for _, variable := range os.Environ() {
				if !strings.HasPrefix(variable, "EIGHTCTL_") {
					command.Env = append(command.Env, variable)
				}
			}
			command.Env = append(command.Env, "EIGHTCTL_TEST_FLAG_CASE="+name)
			if name == "environment fallback" {
				command.Env = append(command.Env, "EIGHTCTL_TIME=09:00")
			}
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("command flags: %v\n%s", err, out)
			}
		})
	}
}
