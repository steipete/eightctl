package client

import (
	"context"
	"net/http"
)

// ListTracks returns audio tracks metadata.
type AudioTrack struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Type  string `json:"type"`
}

func (c *Client) ListTracks(ctx context.Context) ([]AudioTrack, error) {
	path := "/audio/tracks"
	var res struct {
		Tracks []AudioTrack `json:"tracks"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
		return nil, err
	}
	return res.Tracks, nil
}

// ReleaseFeature represents release features payload.
type ReleaseFeature struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func (c *Client) ReleaseFeatures(ctx context.Context) ([]ReleaseFeature, error) {
	path := "/release/features"
	var res struct {
		Features []ReleaseFeature `json:"features"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
		return nil, err
	}
	return res.Features, nil
}
