package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/steipete/eightctl/internal/tokencache"
)

// recordingAPI is a stand-in for the Eight Sleep API that records the bearer
// credential on every request it receives and hands out a fresh token from its
// auth endpoint.
type recordingAPI struct {
	mu        sync.Mutex
	bearers   []string
	authCalls int
	newToken  string
}

func (a *recordingAPI) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/auth") {
			a.mu.Lock()
			a.authCalls++
			a.mu.Unlock()
			fmt.Fprintf(w, `{"access_token":%q,"expires_in":3600,"userId":"uid"}`, a.newToken)
			return
		}
		a.mu.Lock()
		a.bearers = append(a.bearers, r.Header.Get("Authorization"))
		a.mu.Unlock()
		io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)

	prev := authURL
	authURL = srv.URL + "/auth"
	t.Cleanup(func() { authURL = prev })
	return srv
}

func (a *recordingAPI) sawBearer(token string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, got := range a.bearers {
		if got == "Bearer "+token {
			return true
		}
	}
	return false
}

func (a *recordingAPI) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authCalls
}

// newSwitchClient returns a client pointed at srv, built the way the CLI builds one.
func newSwitchClient(srv *httptest.Server) *Client {
	c := New("user@example.test", "pw", "", "cid", "secret")
	c.BaseURL = srv.URL
	c.AppURL = srv.URL
	return c
}

// The authority-chain proof for the backend switch: after logout, a *fresh
// process* must not send the revoked token as a bearer credential, even when
// the run that logged out was pinned to the file backend and the next run is
// not. Asserting on tokencache.Load alone would not show this -- the question
// is what the production client actually puts on the wire.
func TestFreshClientDoesNotSendTokenRevokedWhilePinnedToFile(t *testing.T) {
	primary := keyring.NewArrayKeyring(nil)
	file := keyring.NewArrayKeyring(nil)
	defer tokencache.SetOpenKeyringForTest(func() (keyring.Keyring, error) { return primary, nil })()
	defer tokencache.SetOpenFileKeyringForTest(func() (keyring.Keyring, error) { return file, nil })()
	defer tokencache.SetFileBackendPinForTest(false)()

	const stale = "stale-token-must-not-be-sent"
	api := &recordingAPI{newToken: "fresh-token"}
	srv := api.start(t)
	ctx := context.Background()

	// A previous, unpinned run cached a token in the OS keyring.
	seed := newSwitchClient(srv)
	if err := tokencache.Save(seed.Identity(), stale, time.Now().Add(time.Hour), "uid"); err != nil {
		t.Fatalf("seeding primary backend: %v", err)
	}

	// Non-vacuity: before logout, a fresh client really does send that token.
	before := newSwitchClient(srv)
	if err := before.do(ctx, http.MethodGet, "/probe", nil, nil, nil); err != nil {
		t.Fatalf("pre-logout request: %v", err)
	}
	if !api.sawBearer(stale) {
		t.Fatal("setup is vacuous: the cached token was never sent before logout")
	}
	if api.calls() != 0 {
		t.Fatalf("pre-logout client should have used the cache, not re-authenticated (%d auth calls)", api.calls())
	}

	// This run is pinned to the file backend, as `keyring_backend: file` does,
	// and logs out.
	unpin := tokencache.SetFileBackendPinForTest(true)
	if err := tokencache.Clear(seed.Identity()); err != nil {
		t.Fatalf("logout while pinned to file: %v", err)
	}
	unpin()

	// A later run with the pin removed must re-authenticate, not resurrect the
	// revoked token.
	after := newSwitchClient(srv)
	if err := after.do(ctx, http.MethodGet, "/probe", nil, nil, nil); err != nil {
		t.Fatalf("post-logout request: %v", err)
	}
	if len(api.bearers) < 2 {
		t.Fatalf("expected a post-logout request to reach the API, saw %d", len(api.bearers))
	}
	switch got := api.bearers[len(api.bearers)-1]; got {
	case "Bearer " + stale:
		t.Fatal("a fresh client sent the revoked token after logout across a backend switch")
	case "Bearer fresh-token":
		// Re-authenticated, as it must.
	default:
		t.Fatalf("post-logout request should carry a newly issued token, got %q", got)
	}
	if api.calls() != 1 {
		t.Fatalf("expected exactly one re-authentication after logout, got %d", api.calls())
	}
}

// The refused-deletion half of the same question. When a backend refuses to
// delete, logout must report failure -- because the token survives and a later
// unpinned run will send it. This pins the honest behavior: the error is not
// cosmetic, it predicts what goes on the wire.
func TestRefusedRemovalIsReportedAndTokenStaysUsable(t *testing.T) {
	backing := keyring.NewArrayKeyring(nil)
	refusal := errors.New("keyring refused removal")
	primary := refusingRing{Keyring: backing, err: refusal}
	file := keyring.NewArrayKeyring(nil)
	defer tokencache.SetOpenKeyringForTest(func() (keyring.Keyring, error) { return primary, nil })()
	defer tokencache.SetOpenFileKeyringForTest(func() (keyring.Keyring, error) { return file, nil })()
	defer tokencache.SetFileBackendPinForTest(false)()

	const stale = "token-the-backend-would-not-delete"
	api := &recordingAPI{newToken: "fresh-token"}
	srv := api.start(t)
	ctx := context.Background()

	seed := newSwitchClient(srv)
	if err := tokencache.Save(seed.Identity(), stale, time.Now().Add(time.Hour), "uid"); err != nil {
		t.Fatalf("seeding primary backend: %v", err)
	}

	unpin := tokencache.SetFileBackendPinForTest(true)
	err := tokencache.Clear(seed.Identity())
	unpin()
	if err == nil {
		t.Fatal("logout reported success while the backend refused to delete the token")
	}

	// And the reported failure is truthful: the token is still what goes on the wire.
	after := newSwitchClient(srv)
	if reqErr := after.do(ctx, http.MethodGet, "/probe", nil, nil, nil); reqErr != nil {
		t.Fatalf("post-logout request: %v", reqErr)
	}
	if !api.sawBearer(stale) {
		t.Fatal("expected the surviving token to still be sent, which is what makes the logout error correct")
	}
}

type refusingRing struct {
	keyring.Keyring
	err error
}

func (r refusingRing) Remove(string) error { return r.err }

// The file-backed stale-token case, end to end against the real file backend
// rather than an in-memory store. A token that is still readable but whose
// deletion is denied must not produce a successful logout, because the token
// stays on disk and the very next command sends it as a bearer credential.
func TestFileBackedTokenSurvivingDeniedDeletionIsReportedNotSilentlyReused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not block unlink the same way on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses the directory permissions this test relies on")
	}

	dir := filepath.Join(t.TempDir(), "keyring")
	fileOpener := func() (keyring.Keyring, error) {
		return keyring.Open(keyring.Config{
			ServiceName:      "eightctl-test",
			AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
			FileDir:          dir,
			FilePasswordFunc: func(string) (string, error) { return "test-pass", nil },
		})
	}
	defer tokencache.SetOpenKeyringForTest(func() (keyring.Keyring, error) {
		return nil, errors.New("no OS keyring on this host")
	})()
	defer tokencache.SetOpenFileKeyringForTest(fileOpener)()
	defer tokencache.SetFileBackendPinForTest(true)()

	const stale = "file-token-deletion-denied"
	api := &recordingAPI{newToken: "fresh-token"}
	srv := api.start(t)
	ctx := context.Background()

	seed := newSwitchClient(srv)
	if err := tokencache.Save(seed.Identity(), stale, time.Now().Add(time.Hour), "uid"); err != nil {
		t.Fatalf("seeding real file backend: %v", err)
	}

	// Deny unlink while leaving the stored item readable.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	logoutErr := tokencache.Clear(seed.Identity())

	// The token survived, so a fresh client still puts it on the wire. That is
	// precisely why logout must not have reported success.
	after := newSwitchClient(srv)
	if err := after.do(ctx, http.MethodGet, "/probe", nil, nil, nil); err != nil {
		t.Fatalf("post-logout request: %v", err)
	}
	if !api.sawBearer(stale) {
		t.Fatal("test is vacuous: the surviving token was never sent")
	}
	if logoutErr == nil {
		t.Fatal("logout reported success while a readable token survived and was reused")
	}
}
