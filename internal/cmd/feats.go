package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var featsCmd = &cobra.Command{
	Use:   "feats",
	Short: "List release features",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		feats, err := cl.ReleaseFeatures(context.Background())
		if err != nil {
			return err
		}
		rows := make([]map[string]any, 0, len(feats))
		for _, f := range feats {
			rows = append(rows, map[string]any{"title": f.Title, "body": f.Body})
		}
		return printRows([]string{"title", "body"}, rows)
	},
}
