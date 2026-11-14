//go:build windows

package cmd

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// platformWindowsTimeZoneKey reads TimeZoneKeyName. That value is the
// English Windows zone id, for example "Pacific Standard Time", not an IANA name.
func platformWindowsTimeZoneKey() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	name, _, err := key.GetStringValue("TimeZoneKeyName")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(name)
}
