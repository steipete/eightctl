package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/99designs/keyring"
	"github.com/steipete/eightctl/internal/tokencache"
)

func TestRetryCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		c := New("fixture", "fixture", "uid", "", "")
		c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
		attempts := 0
		c.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader(""))}, nil
		})}
		go func() { time.Sleep(100 * time.Millisecond); cancel() }()
		start := time.Now()
		err := c.do(ctx, http.MethodGet, "/test", nil, nil, nil)
		if !errors.Is(err, context.Canceled) || time.Since(start) != 100*time.Millisecond || attempts != 1 {
			t.Fatalf("error=%v elapsed=%v attempts=%d", err, time.Since(start), attempts)
		}
	})
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestRetryClosesResponseAndReplaysBody(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New("fixture", "fixture", "uid", "", "")
		c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
		var previous *trackedBody
		attempts := 0
		c.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if previous != nil && !previous.closed {
				t.Error("previous response remains open during retry")
			}
			body, err := io.ReadAll(req.Body)
			if err != nil || string(body) != `{"level":12}` {
				t.Fatalf("request body = %s, error = %v", body, err)
			}
			attempts++
			code := http.StatusTooManyRequests
			if attempts == 2 {
				code = http.StatusNoContent
			}
			previous = &trackedBody{Reader: strings.NewReader("")}
			return &http.Response{StatusCode: code, Body: previous}, nil
		})}
		if err := c.do(t.Context(), http.MethodPut, "/test", nil, map[string]int{"level": 12}, nil); err != nil {
			t.Fatal(err)
		}
		if attempts != 2 || !previous.closed {
			t.Fatalf("attempts=%d closed=%v", attempts, previous.closed)
		}
	})
}

type removalDeniedKeyring struct{ keyring.Keyring }

func (removalDeniedKeyring) Remove(string) error { return errors.New("fixture removal denied") }

func TestUnauthorizedReauthenticatesWhenCacheRemovalFails(t *testing.T) {
	ring := removalDeniedKeyring{keyring.NewArrayKeyring(nil)}
	t.Cleanup(tokencache.SetOpenKeyringForTest(func() (keyring.Keyring, error) { return ring, nil }))
	t.Cleanup(tokencache.SetOpenFileKeyringForTest(func() (keyring.Keyring, error) { return ring, nil }))
	c := New("fixture", "fixture", "uid", "", "")
	if err := tokencache.Save(c.Identity(), "rejected", time.Now().Add(time.Hour), "uid"); err != nil {
		t.Fatal(err)
	}
	requests, authentications := 0, 0
	var rejected *trackedBody
	c.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == authURL {
			authentications++
			if rejected != nil && !rejected.closed {
				t.Error("401 response still open during authentication")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"access_token":"fresh","expires_in":3600}`))}, nil
		}
		requests++
		if req.Header.Get("Authorization") == "Bearer fresh" {
			return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		rejected = &trackedBody{Reader: strings.NewReader("")}
		return &http.Response{StatusCode: 401, Body: rejected}, nil
	})}
	if err := c.do(t.Context(), http.MethodGet, "/test", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || authentications != 1 {
		t.Fatalf("requests=%d authentications=%d", requests, authentications)
	}
}
