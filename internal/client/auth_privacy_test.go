package client

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"charm.land/log/v2"
	"github.com/99designs/keyring"
	"github.com/steipete/eightctl/internal/tokencache"
)

func TestAmbiguousCachedAccountsDoNotAuthenticate(t *testing.T) {
	ring := keyring.NewArrayKeyring(nil)
	t.Cleanup(tokencache.SetOpenKeyringForTest(func() (keyring.Keyring, error) { return ring, nil }))
	t.Cleanup(tokencache.SetOpenFileKeyringForTest(func() (keyring.Keyring, error) { return ring, nil }))
	c := New("", "", "", "fixture", "fixture")
	for _, email := range []string{"one@example.invalid", "two@example.invalid"} {
		id := c.Identity()
		id.Email = email
		if err := tokencache.Save(id, "fixture", time.Now().Add(time.Hour), "uid"); err != nil {
			t.Fatal(err)
		}
	}
	c.HTTP = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("ambiguous account triggered a network request")
		return nil, errors.New("unexpected request")
	})}
	if err := c.ensureToken(t.Context()); !errors.Is(err, tokencache.ErrAmbiguousAccount) {
		t.Fatalf("expected actionable account selection error: %v", err)
	}
}

func TestAuthenticationFailureDoesNotLogResponseSecrets(t *testing.T) {
	const marker = "synthetic-private-response"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session="+marker)
		w.Header().Set("X-Debug-Credential", marker)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","password":"` + marker + `"}`))
	}))
	t.Cleanup(server.Close)
	previousURL := authURL
	authURL = server.URL
	t.Cleanup(func() { authURL = previousURL })
	var logs bytes.Buffer
	previousLogger := log.Default()
	logger := log.New(&logs)
	logger.SetLevel(log.DebugLevel)
	log.SetDefault(logger)
	t.Cleanup(func() { log.SetDefault(previousLogger) })

	err := New("fixture", "fixture", "uid", "fixture", "fixture").Authenticate(t.Context())
	if err == nil || !strings.Contains(err.Error(), "400 Bad Request") {
		t.Fatalf("expected HTTP status in authentication failure: %v", err)
	}
	if strings.Contains(logs.String(), marker) || strings.Contains(err.Error(), marker) {
		t.Fatal("authentication failure exposed private response contents")
	}
}
