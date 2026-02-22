package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// resolveTimezone converts a timezone string to a valid IANA timezone name.
// Go's time.Local.String() returns "Local" which is not a valid IANA name
// and is rejected by the Eight Sleep API.
func resolveTimezone(tz string) string {
	if tz != "" && tz != "local" && tz != "Local" {
		return tz
	}
	if iana := localIANA(); iana != "" {
		return iana
	}
	return tz
}

// localIANA detects the IANA timezone name from the operating system.
func localIANA() string {
	if tz := os.Getenv("TZ"); tz != "" && tz != "Local" {
		return tz
	}
	switch runtime.GOOS {
	case "darwin":
		// macOS: /etc/localtime is a symlink into zoneinfo
		target, err := os.Readlink("/etc/localtime")
		if err == nil {
			if idx := strings.Index(target, "zoneinfo/"); idx >= 0 {
				return target[idx+len("zoneinfo/"):]
			}
		}
	case "linux":
		if b, err := os.ReadFile("/etc/timezone"); err == nil {
			if tz := strings.TrimSpace(string(b)); tz != "" {
				return tz
			}
		}
		target, err := filepath.EvalSymlinks("/etc/localtime")
		if err == nil {
			if idx := strings.Index(target, "zoneinfo/"); idx >= 0 {
				return target[idx+len("zoneinfo/"):]
			}
		}
	}
	return ""
}
