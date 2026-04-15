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
	defaultAppURL  = "https://app-api.8slp.net"
	// Extracted from the official Eight Sleep Android app v7.39.17 (public client creds)
	defaultClientID     = "0894c7f33bb94800a03f1f4df13a4f38"
	defaultClientSecret = "f0954a3ed5763ba3d06834c73731a32f15f168f47d4f164751275def86db0c76"
)

// authURL and appAPIBaseURL are vars so tests can point them at local servers.
var (
	authURL       = "https://auth-api.8slp.net/v1/tokens"
	appAPIBaseURL = "https://app-api.8slp.net/v1"
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
	AppURL   string
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
		AppURL:       defaultAppURL,
	}
}

// Authenticate fetches a bearer token via the OAuth password-grant endpoint.
func (c *Client) Authenticate(ctx context.Context) error {
	return c.authTokenEndpoint(ctx)
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
			Devices       []string `json:"devices"`
			CurrentDevice struct {
				ID string `json:"id"`
			} `json:"currentDevice"`
		} `json:"user"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me", nil, nil, &res); err != nil {
		return "", err
	}
	if res.User.CurrentDevice.ID != "" {
		c.DeviceID = res.User.CurrentDevice.ID
		return c.DeviceID, nil
	}
	if len(res.User.Devices) == 0 {
		return "", errors.New("no current device id")
	}
	c.DeviceID = res.User.Devices[0]
	return c.DeviceID, nil
}

func (c *Client) authTokenEndpoint(ctx context.Context) error {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", c.Email)
	form.Set("password", c.Password)
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL,
		bytes.NewReader([]byte(form.Encode())))
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

const maxRetries = 3

// do builds a URL from BaseURL + path and delegates to doURL.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return c.doURL(ctx, method, u, body, out)
}

func (c *Client) doApp(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	u := c.AppURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return c.doURL(ctx, method, u, body, out)
}

// doURL sends an authenticated request to an absolute URL. Use do() for
// BaseURL-relative paths; use doURL directly for requests to other hosts
// (e.g. the app API for away mode).
func (c *Client) doURL(ctx context.Context, method, u string, body any, out any) error {
	return c.doURLRetry(ctx, method, u, body, out, 0)
}

func (c *Client) doURLRetry(ctx context.Context, method, u string, body any, out any, attempt int) error {
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
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "okhttp/4.9.3")
	// Do not set Accept-Encoding explicitly; Go handles gzip transparently.

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		if attempt >= maxRetries {
			return fmt.Errorf("rate limited after %d retries: %s %s", maxRetries, method, u)
		}
		time.Sleep(time.Duration(2*(attempt+1)) * time.Second)
		return c.doURLRetry(ctx, method, u, body, out, attempt+1)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		if attempt >= maxRetries {
			return fmt.Errorf("unauthorized after %d retries: %s %s", maxRetries, method, u)
		}
		c.token = ""
		_ = tokencache.Clear(c.Identity())
		if err := c.ensureToken(ctx); err != nil {
			return err
		}
		return c.doURLRetry(ctx, method, u, body, out, attempt+1)
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("api %s %s: %s", method, u, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// TurnOn powers device on.
func (c *Client) TurnOn(ctx context.Context) error {
	return c.TurnOnForUser(ctx, "")
}

// TurnOff powers device off.
func (c *Client) TurnOff(ctx context.Context) error {
	return c.TurnOffForUser(ctx, "")
}

func (c *Client) TurnOnForUser(ctx context.Context, userID string) error {
	return c.setPowerForUser(ctx, userID, true)
}

func (c *Client) TurnOffForUser(ctx context.Context, userID string) error {
	return c.setPowerForUser(ctx, userID, false)
}

func (c *Client) setPowerForUser(ctx context.Context, userID string, on bool) error {
	targetUserID := userID
	if targetUserID == "" {
		if err := c.requireUser(ctx); err != nil {
			return err
		}
		targetUserID = c.UserID
	}
	path := fmt.Sprintf("/v1/users/%s/temperature", targetUserID)
	state := "off"
	if on {
		state = "smart"
	}
	body := map[string]any{"currentState": map[string]string{"type": state}}
	return c.doApp(ctx, http.MethodPut, path, nil, body, nil)
}

func (c *Client) Identity() tokencache.Identity {
	return tokencache.Identity{
		BaseURL:  c.BaseURL,
		ClientID: c.ClientID,
		Email:    c.Email,
	}
}

// SetTemperature sets target heating/cooling level (-100..100) for the
// authenticated user's current pod side.
func (c *Client) SetTemperature(ctx context.Context, level int) error {
	return c.SetTemperatureForUser(ctx, "", level)
}

// SetTemperatureForUser sets target heating/cooling level (-100..100) for a
// specific household user ID. If userID is empty, the authenticated user's ID
// is resolved and used.
func (c *Client) SetTemperatureForUser(ctx context.Context, userID string, level int) error {
	if level < -100 || level > 100 {
		return fmt.Errorf("level must be between -100 and 100")
	}
	targetUserID := userID
	if targetUserID == "" {
		if err := c.requireUser(ctx); err != nil {
			return err
		}
		targetUserID = c.UserID
	}
	path := fmt.Sprintf("/v1/users/%s/temperature", targetUserID)
	if err := c.doApp(ctx, http.MethodPut, path, nil, map[string]any{
		"currentState": map[string]string{"type": "smart"},
	}, nil); err != nil {
		return err
	}
	body := map[string]int{"currentLevel": level}
	return c.doApp(ctx, http.MethodPut, path, nil, body, nil)
}

// SetAwayMode activates or deactivates away mode for a specific user ID.
// The away-mode endpoint lives on the app API (app-api.8slp.net), not the
// client API used by most other endpoints.
// If userID is empty, it defaults to the authenticated user.
func (c *Client) SetAwayMode(ctx context.Context, userID string, away bool) error {
	if userID == "" {
		if err := c.requireUser(ctx); err != nil {
			return err
		}
		userID = c.UserID
	}
	ts := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02T15:04:05.000Z")
	var payload map[string]any
	if away {
		payload = map[string]any{"awayPeriod": map[string]string{"start": ts}}
	} else {
		payload = map[string]any{"awayPeriod": map[string]string{"end": ts}}
	}
	u := fmt.Sprintf("%s/users/%s/away-mode", appAPIBaseURL, userID)
	return c.doURL(ctx, http.MethodPut, u, payload, nil)
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
	return c.GetStatusForUser(ctx, "")
}

func (c *Client) GetStatusForUser(ctx context.Context, userID string) (*TempStatus, error) {
	targetUserID := userID
	if targetUserID == "" {
		if err := c.requireUser(ctx); err != nil {
			return nil, err
		}
		targetUserID = c.UserID
	}
	path := fmt.Sprintf("/v1/users/%s/temperature", targetUserID)
	var res TempStatus
	if err := c.doApp(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
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
	q.Set("tz", resolveTZ(timezone))
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

// resolveTZ converts the CLI-convention zone "" or "local" to an IANA zone
// name. Eight Sleep's tz param rejects the literal strings "local" and
// "Local" (the latter is what time.Local.String() returns when the system
// has no zoneinfo). UTC is used as a last-resort fallback and logged so
// off-by-hours trend data is not presented as correct.
func resolveTZ(tz string) string {
	if tz != "" && tz != "local" {
		return tz
	}
	name := time.Local.String()
	if name == "" || name == "Local" {
		log.Warn("system timezone unresolved; defaulting to UTC. Pass --timezone <IANA> to override.")
		return "UTC"
	}
	return name
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
