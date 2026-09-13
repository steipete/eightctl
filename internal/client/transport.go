package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/steipete/eightctl/internal/tokencache"
)

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
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
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
		// Leave Accept-Encoding to Go so gzip responses are decoded transparently.
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return err
		}
		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			resp.Body.Close()
			if attempt >= maxRetries {
				return fmt.Errorf("rate limited after %d retries: %s %s", maxRetries, method, u)
			}
			timer := time.NewTimer(time.Duration(2*(attempt+1)) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		case http.StatusUnauthorized:
			resp.Body.Close()
			if attempt >= maxRetries {
				return fmt.Errorf("unauthorized after %d retries: %s %s", maxRetries, method, u)
			}
			c.token = ""
			_ = tokencache.Clear(c.Identity())
			// A failed cache removal must not reload the token the server just rejected.
			if err := c.Authenticate(ctx); err != nil {
				return err
			}
		default:
			defer resp.Body.Close()
			if resp.StatusCode >= 300 {
				b, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("api %s %s: %s", method, u, string(b))
			}
			if out != nil {
				return json.NewDecoder(resp.Body).Decode(out)
			}
			return nil
		}
	}
}
