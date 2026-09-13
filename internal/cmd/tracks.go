package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
)

var tracksCmd = &cobra.Command{
	Use:   "tracks",
	Short: "List audio tracks",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireAuthFields(); err != nil {
			return err
		}
		cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
		tracks, err := cl.ListTracks(context.Background())
		if err != nil {
			return err
		}
		rows := make([]map[string]any, 0, len(tracks))
		for _, t := range tracks {
			rows = append(rows, map[string]any{"id": t.ID, "title": t.Title, "type": t.Type})
		}
		return printRows([]string{"id", "title", "type"}, rows)
	},
}
