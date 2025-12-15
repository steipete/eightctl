package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/charmbracelet/log"
	"github.com/steipete/eightctl/internal/tokencache"
)

const (
	defaultBaseURL = "https://client-api.8slp.net/v1"
	authURL        = "https://auth-api.8slp.net/v1/tokens"
	// Extracted from the official Eight Sleep Android app v7.39.17 (public client creds)
	defaultClientID     = "0894c7f33bb94800a03f1f4df13a4f38"
	defaultClientSecret = "f0954a3ed5763ba3d06834c73731a32f15f168f47d4f164751275def86db0c76"
)

// Client represents Eight Sleep API client.
type Client struct {
	Email        string
	Password     string
	UserID       string
	ClientID     string
	ClientSecret string
	DeviceID     string

	HTTP     *http.Client
	BaseURL  string
	token    string
	tokenExp time.Time
}

// New creates a Client.

func New(email, password, userID, clientID, clientSecret string) *Client {
	if clientID == "" {
		clientID = defaultClientID
	}
	if clientSecret == "" {
		clientSecret = defaultClientSecret
	}
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		// Disable HTTP/2; Eight Sleep frontends sometimes hang on H2 with Go.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &Client{
		Email:        email,
		Password:     password,
		UserID:       userID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTP:         &http.Client{Timeout: 20 * time.Second, Transport: tr},
		BaseURL:      defaultBaseURL,
	}
}

// Authenticate fetches bearer token. First checks cache, then tries OAuth token endpoint, falls back to /login.
func (c *Client) Authenticate(ctx context.Context) error {
	// Check in-memory token first
	if c.token != "" && time.Now().Before(c.tokenExp) {
		log.Debug("using in-memory token", "expires_in", time.Until(c.tokenExp).Round(time.Second))
		return nil
	}
	// Check cached token from keychain
	if cached, err := tokencache.Load(c.Identity(), c.UserID); err == nil {
		log.Debug("loaded token from cache", "expires_at", cached.ExpiresAt, "user_id", cached.UserID)
		c.token = cached.Token
		c.tokenExp = cached.ExpiresAt
		if cached.UserID != "" && c.UserID == "" {
			c.UserID = cached.UserID
		}
		return nil
	}
	// Authenticate with server
	log.Debug("authenticating with server")
	if err := c.authTokenEndpoint(ctx); err == nil {
		return nil
	}
	return c.authLegacyLogin(ctx)
}

// EnsureUserID populates UserID by calling /users/me if missing.
func (c *Client) EnsureUserID(ctx context.Context) error {
	if c.UserID != "" {
		return nil
	}
	var res struct {
		User struct {
			UserID string `json:"userId"`
		} `json:"user"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me", nil, nil, &res); err != nil {
		return err
	}
	if res.User.UserID == "" {
		return errors.New("userId not found")
	}
	c.UserID = res.User.UserID
	return nil
}

// EnsureDeviceID fetches current device id if not already set.
func (c *Client) EnsureDeviceID(ctx context.Context) (string, error) {
	if c.DeviceID != "" {
		return c.DeviceID, nil
	}
	var res struct {
		User struct {
			CurrentDevice struct {
				ID string `json:"id"`
			} `json:"currentDevice"`
		} `json:"user"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me", nil, nil, &res); err != nil {
		return "", err
	}
	if res.User.CurrentDevice.ID == "" {
		return "", errors.New("no current device id")
	}
	c.DeviceID = res.User.CurrentDevice.ID
	return c.DeviceID, nil
}

func (c *Client) authTokenEndpoint(ctx context.Context) error {
	payload := map[string]string{
		"grant_type":    "password",
		"username":      c.Email,
		"password":      c.Password,
		"client_id":     "sleep-client",
		"client_secret": "",
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

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

func (c *Client) authLegacyLogin(ctx context.Context) error {
	payload := map[string]string{
		"email":    c.Email,
		"password": c.Password,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "okhttp/4.9.3")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		log.Debug("legacy login failed", "status", resp.Status, "headers", resp.Header, "body", string(b))
		return fmt.Errorf("login failed: %s", string(b))
	}
	var res struct {
		Session struct {
			UserID         string `json:"userId"`
			Token          string `json:"token"`
			ExpirationDate string `json:"expirationDate"`
		} `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}
	if res.Session.Token == "" {
		return errors.New("empty session token")
	}
	c.token = res.Session.Token
	if res.Session.ExpirationDate != "" {
		if t, err := time.Parse(time.RFC3339, res.Session.ExpirationDate); err == nil {
			c.tokenExp = t
		}
	}
	if c.tokenExp.IsZero() {
		c.tokenExp = time.Now().Add(12 * time.Hour)
	}
	if c.UserID == "" {
		c.UserID = res.Session.UserID
	}
	if err := tokencache.Save(c.Identity(), c.token, c.tokenExp, c.UserID); err != nil {
		log.Debug("failed to cache token", "error", err)
	} else {
		log.Debug("saved token to cache (legacy)", "expires_at", c.tokenExp)
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
	if cached, err := tokencache.Load(c.Identity(), c.UserID); err == nil {
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

// requireUser ensures UserID is populated.
func (c *Client) requireUser(ctx context.Context) error {
	if c.UserID != "" {
		return nil
	}
	return c.EnsureUserID(ctx)
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	if err := c.ensureToken(ctx); err != nil {
		return err
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "okhttp/4.9.3")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		time.Sleep(2 * time.Second)
		return c.do(ctx, method, path, query, body, out)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		log.Debug("api returned 401, clearing token", "method", method, "path", path, "body", string(b))
		c.token = ""
		_ = tokencache.Clear(c.Identity())
		if err := c.ensureToken(ctx); err != nil {
			return err
		}
		return c.do(ctx, method, path, query, body, out)
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("api %s %s: %s", method, path, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// TurnOn powers device on.
func (c *Client) TurnOn(ctx context.Context) error {
	return c.setPower(ctx, true)
}

// TurnOff powers device off.
func (c *Client) TurnOff(ctx context.Context) error {
	return c.setPower(ctx, false)
}

func (c *Client) setPower(ctx context.Context, on bool) error {
	if err := c.requireUser(ctx); err != nil {
		return err
	}
	path := fmt.Sprintf("/users/%s/devices/power", c.UserID)
	body := map[string]bool{"on": on}
	return c.do(ctx, http.MethodPost, path, nil, body, nil)
}

func (c *Client) Identity() tokencache.Identity {
	return tokencache.Identity{
		BaseURL:  c.BaseURL,
		ClientID: c.ClientID,
		Email:    c.Email,
	}
}

// SetTemperature sets target heating/cooling level (-100..100).
func (c *Client) SetTemperature(ctx context.Context, level int) error {
	if err := c.requireUser(ctx); err != nil {
		return err
	}
	if level < -100 || level > 100 {
		return fmt.Errorf("level must be between -100 and 100")
	}
	path := fmt.Sprintf("/users/%s/temperature", c.UserID)
	body := map[string]int{"currentLevel": level}
	return c.do(ctx, http.MethodPut, path, nil, body, nil)
}

// TempStatus represents current temperature state payload.
type TempStatus struct {
	CurrentLevel int `json:"currentLevel"`
	CurrentState struct {
		Type string `json:"type"`
	} `json:"currentState"`
}

// GetStatus fetches temperature-based status (current mode/level).
func (c *Client) GetStatus(ctx context.Context) (*TempStatus, error) {
	if err := c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/users/%s/temperature", c.UserID)
	var res TempStatus
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// SleepDay represents aggregated sleep metrics for a day.
type SleepDay struct {
	Date          string  `json:"day"`
	Score         float64 `json:"score"`
	Tnt           int     `json:"tnt"`
	Respiratory   float64 `json:"respiratoryRate"`
	HeartRate     float64 `json:"heartRate"`
	LatencyAsleep float64 `json:"latencyAsleepSeconds"`
	LatencyOut    float64 `json:"latencyOutSeconds"`
	Duration      float64 `json:"sleepDurationSeconds"`
	Stages        []Stage `json:"stages"`
	SleepQuality  struct {
		HRV struct {
			Score float64 `json:"score"`
		} `json:"hrv"`
		Resp struct {
			Score float64 `json:"score"`
		} `json:"respiratoryRate"`
	} `json:"sleepQualityScore"`
}

// Stage represents sleep stage duration.
type Stage struct {
	Stage    string  `json:"stage"`
	Duration float64 `json:"duration"`
}

// GetSleepDay fetches sleep trends for a date (YYYY-MM-DD).
func (c *Client) GetSleepDay(ctx context.Context, date string, timezone string) (*SleepDay, error) {
	if err := c.requireUser(ctx); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("tz", timezone)
	q.Set("from", date)
	q.Set("to", date)
	q.Set("include-main", "false")
	q.Set("include-all-sessions", "true")
	q.Set("model-version", "v2")
	path := fmt.Sprintf("/users/%s/trends", c.UserID)
	var res struct {
		Days []SleepDay `json:"days"`
	}
	if err := c.do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
		return nil, err
	}
	if len(res.Days) == 0 {
		return nil, fmt.Errorf("no sleep data for %s", date)
	}
	return &res.Days[0], nil
}

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
