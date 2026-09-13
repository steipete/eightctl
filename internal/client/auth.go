package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"charm.land/log/v2"
	"github.com/steipete/eightctl/internal/tokencache"
)

// Authenticate fetches a bearer token via the OAuth password-grant endpoint.
func (c *Client) Authenticate(ctx context.Context) error {
	return c.authTokenEndpoint(ctx)
}

func (c *Client) authTokenEndpoint(ctx context.Context) error {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", c.Email)
	form.Set("password", c.Password)
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		log.Debug("token auth failed", "status", resp.Status, "headers", resp.Header, "body", string(b))
		return fmt.Errorf("token auth failed: %s", resp.Status)
	}

	var res struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		UserID      string `json:"userId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}
	if res.AccessToken == "" {
		return errors.New("empty access token")
	}
	c.token = res.AccessToken
	if res.ExpiresIn == 0 {
		res.ExpiresIn = 3600
	}
	c.tokenExp = time.Now().Add(time.Duration(res.ExpiresIn-60) * time.Second)
	if c.UserID == "" {
		c.UserID = res.UserID
	}
	if err := tokencache.Save(c.Identity(), c.token, c.tokenExp, c.UserID); err != nil {
		log.Debug("failed to cache token", "error", err)
	} else {
		log.Debug("saved token to cache", "expires_at", c.tokenExp)
	}
	return nil
}

func (c *Client) ensureToken(ctx context.Context) error {
	if c.token != "" && time.Now().Before(c.tokenExp) {
		log.Debug("using in-memory token", "expires_in", time.Until(c.tokenExp).Round(time.Second))
		return nil
	}
	// Trust cached tokens without server validation. If token is invalid,
	// the server will return 401 and we'll clear cache + re-authenticate.
	if cached, err := tokencache.Load(c.Identity()); err == nil {
		log.Debug("loaded token from cache", "expires_at", cached.ExpiresAt, "user_id", cached.UserID)
		c.token = cached.Token
		c.tokenExp = cached.ExpiresAt
		if cached.UserID != "" && c.UserID == "" {
			c.UserID = cached.UserID
		}
		return nil
	} else {
		log.Debug("no cached token", "reason", err)
	}
	log.Debug("authenticating with server")
	return c.Authenticate(ctx)
}

func (c *Client) Identity() tokencache.Identity {
	return tokencache.Identity{
		BaseURL:  c.BaseURL,
		ClientID: c.ClientID,
		Email:    c.Email,
	}
}
