package cmd

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/tokencache"
)

func TestRequireAuthFieldsReportsAmbiguousAccounts(t *testing.T) {
	useTempKeyring(t)
	resetViper(t)
	for _, email := range []string{"one@example.invalid", "two@example.invalid"} {
		cl := client.New(email, "", "", "", "")
		if err := tokencache.Save(cl.Identity(), "fixture", time.Now().Add(time.Hour), "uid"); err != nil {
			t.Fatal(err)
		}
	}
	if err := requireAuthFields(); !errors.Is(err, tokencache.ErrAmbiguousAccount) {
		t.Fatalf("expected actionable account selection error: %v", err)
	}
}

func useTempKeyring(t *testing.T) func() {
	t.Helper()
	tmp := t.TempDir()
	opener := func() (keyring.Keyring, error) {
		return keyring.Open(keyring.Config{
			ServiceName:      "eightctl-test",
			AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
			FileDir:          filepath.Join(tmp, "keyring"),
			FilePasswordFunc: func(_ string) (string, error) { return "test-pass", nil },
		})
	}
	restore := tokencache.SetOpenKeyringForTest(opener)
	restoreFile := tokencache.SetOpenFileKeyringForTest(opener)
	t.Cleanup(restore)
	t.Cleanup(restoreFile)
	return restore
}

func resetViper(t *testing.T) {
	t.Helper()
	viper.Reset()
}

func TestRequireAuthFieldsPassesWithCachedToken(t *testing.T) {
	useTempKeyring(t)
	resetViper(t)

	// Save a cached token without setting credentials.
	cl := client.New("", "", "", "", "")
	if err := tokencache.Save(cl.Identity(), "tok", time.Now().Add(time.Hour), "cached-user"); err != nil {
		t.Fatalf("save cache: %v", err)
	}

	if err := requireAuthFields(); err != nil {
		t.Fatalf("requireAuthFields should pass with cache: %v", err)
	}
	if got := viper.GetString("user_id"); got != "cached-user" {
		t.Fatalf("user_id not propagated from cache, got %q", got)
	}
}

func TestRequireAuthFieldsFailsWithoutCacheOrCreds(t *testing.T) {
	useTempKeyring(t)
	resetViper(t)

	err := requireAuthFields()
	if err == nil {
		t.Fatalf("expected missing credentials error")
	}
}

// When an explicit user_id is already set (e.g. via --user-id or config),
// the cached UserID must not overwrite it. Households share one cached token
// across multiple userIDs, so clobbering would silently retarget commands.
func TestRequireAuthFieldsDoesNotClobberExplicitUserID(t *testing.T) {
	useTempKeyring(t)
	resetViper(t)

	viper.Set("user_id", "explicit-user")

	cl := client.New("", "", "explicit-user", "", "")
	if err := tokencache.Save(cl.Identity(), "tok", time.Now().Add(time.Hour), "cached-user"); err != nil {
		t.Fatalf("save cache: %v", err)
	}

	if err := requireAuthFields(); err != nil {
		t.Fatalf("requireAuthFields should pass with cache: %v", err)
	}
	if got := viper.GetString("user_id"); got != "explicit-user" {
		t.Fatalf("explicit user_id was overwritten, got %q", got)
	}
}
