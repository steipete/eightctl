package cmd

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/tokencache"
)

func TestInvalidHouseholdIdentityDoesNotFallBackToAuthenticatedUser(t *testing.T) {
	useTempKeyring(t)
	requests := make(chan string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
		if r.URL.Path == "/devices/dev" {
			w.Write([]byte(`{"result":{"leftUserId":"selected-user"}}`))
		} else {
			w.Write([]byte(`{"user":{}}`))
		}
	}))
	defer server.Close()
	c := client.New("fixture", "fixture", "authenticated-user", "", "")
	c.BaseURL, c.AppURL, c.DeviceID, c.HTTP = server.URL, server.URL, "dev", server.Client()
	if err := tokencache.Save(c.Identity(), "fixture", time.Now().Add(time.Hour), c.UserID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveCommandTargetValues(t.Context(), c, "", ""); !errors.Is(err, client.ErrInvalidHouseholdUser) {
		t.Fatalf("control resolution: %v", err)
	}
	if _, _, err := defaultStatusRows(t.Context(), c, nil); !errors.Is(err, client.ErrInvalidHouseholdUser) {
		t.Fatalf("status resolution: %v", err)
	}
	close(requests)
	for path := range requests {
		if strings.Contains(path, "temperature") {
			t.Fatalf("fell back to a different target: %s", path)
		}
	}
}
