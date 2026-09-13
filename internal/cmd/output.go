package cmd

import (
	"github.com/spf13/viper"
	"github.com/steipete/eightctl/internal/output"
)

func printRows(headers []string, rows []map[string]any) error {
	return output.PrintFields(output.Format(viper.GetString("output")), headers, rows, viper.GetStringSlice("fields"))
}
