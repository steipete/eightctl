package cmd

import (
	"strings"
	"time"
)

func resolveAPITimezone(value string) (string, error) {
	tz := strings.TrimSpace(value)
	if tz == "" || strings.EqualFold(tz, "local") {
		tz = strings.TrimSpace(time.Now().Location().String())
	}
	if tz == "" || strings.EqualFold(tz, "local") {
		logger.Warn("system local timezone is not an IANA zone; falling back to UTC for API queries")
		return "UTC", nil
	}
	return tz, nil
}

func currentDate() string {
	return time.Now().Format("2006-01-02")
}
