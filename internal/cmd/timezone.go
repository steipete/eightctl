package cmd

import (
	"fmt"
	"strings"
	"time"
)

func resolveAPITimezone(value string) (string, error) {
	tz := strings.TrimSpace(value)
	if tz == "" || strings.EqualFold(tz, "local") {
		tz = strings.TrimSpace(time.Local.String())
	}
	if tz == "" || strings.EqualFold(tz, "local") {
		return "", fmt.Errorf("timezone must be an explicit IANA timezone for sleep/metrics queries on this system; set --timezone or EIGHTCTL_TIMEZONE, e.g. America/New_York")
	}
	return tz, nil
}

func currentDate() string {
	return time.Now().Format("2006-01-02")
}
