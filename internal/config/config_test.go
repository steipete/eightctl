package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestLoadReadsConfigAndEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(strings.Join([]string{
		"email: file@example.com",
		"password: file-pass",
		"user_id: user-file",
		"timezone: Europe/Vienna",
		"output: json",
		"fields:",
		"  - score",
		"verbose: true",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("EIGHTCTL_PASSWORD", "env-pass")

	got, err := Load(viper.New(), cfgPath, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Email != "file@example.com" {
		t.Fatalf("Email = %q", got.Email)
	}
	if got.Password != "env-pass" {
		t.Fatalf("Password = %q, want env override", got.Password)
	}
	if got.UserID != "user-file" || got.Timezone != "Europe/Vienna" || got.Output != "json" || !got.Verbose {
		t.Fatalf("config = %+v", got)
	}
	if len(got.Fields) != 1 || got.Fields[0] != "score" {
		t.Fatalf("Fields = %#v", got.Fields)
	}
}

func TestLoadDefaultsWhenConfigMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	got, err := Load(viper.New(), "", true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Timezone != "local" || got.Output != "table" {
		t.Fatalf("defaults = %+v", got)
	}
}

func TestWarnInsecurePerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("email: x"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := WarnInsecurePerms(path); err == nil {
		t.Fatalf("expected insecure permission warning")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := WarnInsecurePerms(path); err != nil {
		t.Fatalf("WarnInsecurePerms secure file: %v", err)
	}
	if err := WarnInsecurePerms(filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatalf("missing file should not warn: %v", err)
	}
	if err := WarnInsecurePerms(""); err != nil {
		t.Fatalf("empty path should not warn: %v", err)
	}
}
