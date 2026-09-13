package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/output"
)

var audioCmd = &cobra.Command{Use: "audio", Short: "Audio tracks and player"}

var audioTracksCmd = &cobra.Command{Use: "tracks", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	tracks, err := cl.Audio().Tracks(context.Background())
	if err != nil {
		return err
	}
	rows := make([]map[string]any, 0, len(tracks))
	for _, t := range tracks {
		rows = append(rows, map[string]any{"id": t.ID, "title": t.Title, "type": t.Type})
	}
	rows = output.FilterFields(rows, viper.GetStringSlice("fields"))
	headers := viper.GetStringSlice("fields")
	if len(headers) == 0 {
		headers = []string{"id", "title", "type"}
	}
	return output.Print(output.Format(viper.GetString("output")), headers, rows)
}}

var audioCategoriesCmd = &cobra.Command{Use: "categories", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Audio().Categories(context.Background())
	if err != nil {
		return err
	}
	rows := []map[string]any{{"data": res}}
	return output.Print(output.Format(viper.GetString("output")), []string{"data"}, rows)
}}

var audioStateCmd = &cobra.Command{Use: "state", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Audio().PlayerState(context.Background())
	if err != nil {
		return err
	}
	rows := []map[string]any{{"state": res}}
	return output.Print(output.Format(viper.GetString("output")), []string{"state"}, rows)
}}

var audioPlayCmd = &cobra.Command{Use: "play", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	track := viper.GetString("track")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Audio().Play(context.Background(), track)
}}

var audioPauseCmd = &cobra.Command{Use: "pause", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Audio().Pause(context.Background())
}}

var audioSeekCmd = &cobra.Command{Use: "seek", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	pos := viper.GetInt("position")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Audio().Seek(context.Background(), pos)
}}

var audioVolumeCmd = &cobra.Command{Use: "volume", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	lvl := viper.GetInt("level")
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Audio().Volume(context.Background(), lvl)
}}

var audioPairCmd = &cobra.Command{Use: "pair", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Audio().Pair(context.Background())
}}

var audioNextCmd = &cobra.Command{Use: "next", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Audio().RecommendedNext(context.Background())
	if err != nil {
		return err
	}
	rows := []map[string]any{{"next": res}}
	return output.Print(output.Format(viper.GetString("output")), []string{"next"}, rows)
}}

var audioFavoritesCmd = &cobra.Command{Use: "favorites", Short: "Favorite tracks"}

var audioFavListCmd = &cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	res, err := cl.Audio().Favorites(context.Background())
	if err != nil {
		return err
	}
	return output.Print(output.Format(viper.GetString("output")), []string{"favorites"}, []map[string]any{{"favorites": res}})
}}

var audioFavAddCmd = &cobra.Command{Use: "add", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	id := viper.GetString("track")
	if id == "" {
		return fmt.Errorf("--track required")
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Audio().AddFavorite(context.Background(), id)
}}

var audioFavRemoveCmd = &cobra.Command{Use: "remove", RunE: func(cmd *cobra.Command, args []string) error {
	if err := requireAuthFields(); err != nil {
		return err
	}
	id := viper.GetString("track")
	if id == "" {
		return fmt.Errorf("--track required")
	}
	cl := client.New(viper.GetString("email"), viper.GetString("password"), viper.GetString("user_id"), viper.GetString("client_id"), viper.GetString("client_secret"))
	return cl.Audio().RemoveFavorite(context.Background(), id)
}}

func init() {
	audioPlayCmd.Flags().String("track", "", "track ID to play")
	audioSeekCmd.Flags().Int("position", 0, "position milliseconds")
	audioVolumeCmd.Flags().Int("level", 50, "volume level 0-100")
	audioFavAddCmd.Flags().String("track", "", "track id")
	audioFavRemoveCmd.Flags().String("track", "", "track id")

	audioFavoritesCmd.AddCommand(audioFavListCmd, audioFavAddCmd, audioFavRemoveCmd)
	audioCmd.AddCommand(audioTracksCmd, audioCategoriesCmd, audioStateCmd, audioPlayCmd, audioPauseCmd, audioSeekCmd, audioVolumeCmd, audioPairCmd, audioNextCmd, audioFavoritesCmd)
}
