//go:build !windows

package cmd

// Non-Windows builds have no TimeZoneKeyName. Tests replace readWindowsTimeZoneKey.
func platformWindowsTimeZoneKey() string { return "" }
