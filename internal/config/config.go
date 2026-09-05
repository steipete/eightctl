package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds merged configuration.
type Config struct {
	Email        string   `mapstructure:"email"`
	Password     string   `mapstructure:"password"`
	UserID       string   `mapstructure:"user_id"`
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	Timezone     string   `mapstructure:"timezone"`
	Output       string   `mapstructure:"output"`
	Fields       []string `mapstructure:"fields"`
	Verbose      bool     `mapstructure:"verbose"`
	// KeyringBackend selects where the cached auth token lives. "file" pins the
	// file backend and never touches the OS keyring; empty keeps the default
	// (OS keyring first, file as fallback). Env: EIGHTCTL_KEYRING_BACKEND.
	KeyringBackend string `mapstructure:"keyring_backend"`
}

// Load configures v, reads the selected file, and unmarshals Config.
func Load(v *viper.Viper, configPath string, quiet bool) (Config, error) {
	v.SetConfigType("yaml")
	v.SetEnvPrefix("EIGHTCTL")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return Config{}, fmt.Errorf("find home: %w", err)
		}
		v.AddConfigPath(filepath.Join(home, ".config", "eightctl"))
		v.SetConfigName("config")
	}

	// defaults
	v.SetDefault("timezone", "local")
	v.SetDefault("output", "table")

	if err := v.ReadInConfig(); err == nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "Using config file: %s\n", v.ConfigFileUsed())
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	return cfg, nil
}

// WarnInsecurePerms checks if config file is too permissive.
func WarnInsecurePerms(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf("config file %s permissions %o; suggest 600", path, mode)
	}
	return nil
}
