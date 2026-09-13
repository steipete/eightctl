package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func resolveAPITimezone(value string) (string, error) {
	tz := strings.TrimSpace(value)
	if tz != "" && !strings.EqualFold(tz, "local") {
		return tz, nil
	}
	if iana := localIANA(); iana != "" {
		return iana, nil
	}
	if loc := strings.TrimSpace(time.Now().Location().String()); loc != "" && !strings.EqualFold(loc, "local") {
		return loc, nil
	}
	logger.Warn("system local timezone is not an IANA zone; falling back to UTC for API queries")
	return "UTC", nil
}

// localIANA is overridable in tests.
var localIANA = defaultLocalIANA

// defaultLocalIANA discovers the IANA zone name the OS considers local. Go's
// time.Local.String() reports "Local" when TZ is unset, which the Eight Sleep
// API rejects, so we read the platform-specific source of truth.
func defaultLocalIANA() string {
	if tz := strings.TrimSpace(os.Getenv("TZ")); tz != "" && !strings.EqualFold(tz, "local") {
		return tz
	}
	switch runtime.GOOS {
	case "darwin":
		if target, err := os.Readlink("/etc/localtime"); err == nil {
			if zone := extractZoneinfoSuffix(target); zone != "" {
				return zone
			}
		}
	case "linux":
		if b, err := os.ReadFile("/etc/timezone"); err == nil {
			if zone := strings.TrimSpace(string(b)); zone != "" {
				return zone
			}
		}
		if target, err := filepath.EvalSymlinks("/etc/localtime"); err == nil {
			if zone := extractZoneinfoSuffix(target); zone != "" {
				return zone
			}
		}
	}
	return ""
}

func extractZoneinfoSuffix(path string) string {
	const marker = "zoneinfo/"
	if idx := strings.Index(path, marker); idx >= 0 {
		return path[idx+len(marker):]
	}
	return ""
}

func currentDate(timezone string) (string, error) {
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return "", fmt.Errorf("load timezone %q: %w", timezone, err)
	}
	return time.Now().In(location).Format(time.DateOnly), nil
}
