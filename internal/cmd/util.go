package cmd

import (
	"maps"
	"slices"
)

func mapKeys(m map[string]any) []string {
	return slices.Sorted(maps.Keys(m))
}
