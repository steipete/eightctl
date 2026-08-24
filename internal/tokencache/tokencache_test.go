package tokencache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/99designs/keyring"
)

func withTestKeyring(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()
	opener := func() (keyring.Keyring, error) {
		return keyring.Open(keyring.Config{
			ServiceName:      serviceName + "-test",
			AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
			FileDir:          filepath.Join(tmpDir, "keyring"),
			FilePasswordFunc: func(_ string) (string, error) { return "test-pass", nil },
		})
	}
	origKeyring := openKeyring
	origFile := openFileKeyring
	openKeyring = opener
	openFileKeyring = opener
	t.Cleanup(func() {
		openKeyring = origKeyring
		openFileKeyring = origFile
	})
}

func TestSaveLoadRoundTrip(t *testing.T) {
	withTestKeyring(t)

	id := Identity{BaseURL: "https://api.example.com", ClientID: "client-1", Email: "User@Example.com"}
	exp := time.Now().Add(time.Hour)

	if err := Save(id, "token-123", exp, "user-1"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Token != "token-123" {
		t.Errorf("token = %q, want token-123", got.Token)
	}
	if !got.ExpiresAt.Equal(exp) {
		t.Errorf("expiresAt = %v, want %v", got.ExpiresAt, exp)
	}
	if got.UserID != "user-1" {
		t.Errorf("userID = %q, want user-1", got.UserID)
	}
}

// Households share one OAuth principal (email) across multiple userIDs, so a
// token saved under "user-a" must still satisfy Load when the current call is
// targeting "user-b". Identity-level namespacing is the authoritative boundary.
func TestLoadReturnsTokenRegardlessOfStoredUserID(t *testing.T) {
	withTestKeyring(t)
	id := Identity{BaseURL: "https://api.example.com", ClientID: "client-1"}
	if err := Save(id, "token", time.Now().Add(time.Hour), "user-a"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Token != "token" {
		t.Errorf("token = %q, want token", got.Token)
	}
	if got.UserID != "user-a" {
		t.Errorf("UserID metadata = %q, want user-a", got.UserID)
	}
}

func TestLoadExpiredRemovesEntry(t *testing.T) {
	withTestKeyring(t)
	id := Identity{BaseURL: "https://api.example.com", ClientID: "client-1"}
	if err := Save(id, "expired", time.Now().Add(-time.Minute), "user-1"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := Load(id); err != keyring.ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound for expired token, got %v", err)
	}
	// second load should still be ErrKeyNotFound (entry removed)
	if _, err := Load(id); err != keyring.ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound after removal, got %v", err)
	}
}

func TestClearIgnoresMissing(t *testing.T) {
	withTestKeyring(t)
	id := Identity{BaseURL: "https://api.example.com", ClientID: "client-1"}
	if err := Clear(id); err != nil {
		t.Fatalf("Clear missing: %v", err)
	}
}

func TestNamespacingByIdentity(t *testing.T) {
	withTestKeyring(t)
	idA := Identity{BaseURL: "https://api.example.com", ClientID: "client-1", Email: "a@example.com"}
	idB := Identity{BaseURL: "https://api.example.com", ClientID: "client-2", Email: "a@example.com"}
	idC := Identity{BaseURL: "https://api.example.com", ClientID: "client-1", Email: "b@example.com"}
	idD := Identity{BaseURL: "https://api.example.com", ClientID: "client-1", Email: ""}

	if err := Save(idA, "token-a", time.Now().Add(time.Hour), "user-a"); err != nil {
		t.Fatalf("Save A: %v", err)
	}
	if err := Save(idB, "token-b", time.Now().Add(time.Hour), "user-b"); err != nil {
		t.Fatalf("Save B: %v", err)
	}
	if err := Save(idC, "token-c", time.Now().Add(time.Hour), "user-c"); err != nil {
		t.Fatalf("Save C: %v", err)
	}
	if err := Save(idD, "token-d", time.Now().Add(time.Hour), "user-d"); err != nil {
		t.Fatalf("Save D: %v", err)
	}

	if got, _ := Load(idA); got.Token != "token-a" {
		t.Errorf("Load A token = %q, want token-a", got.Token)
	}
	if got, _ := Load(idB); got.Token != "token-b" {
		t.Errorf("Load B token = %q, want token-b", got.Token)
	}
	if got, _ := Load(idC); got.Token != "token-c" {
		t.Errorf("Load C token = %q, want token-c", got.Token)
	}
	if got, _ := Load(idD); got.Token != "token-d" {
		t.Errorf("Load D token = %q, want token-d", got.Token)
	}
}

func TestClearOnlyRemovesMatchingIdentity(t *testing.T) {
	withTestKeyring(t)
	idA := Identity{BaseURL: "https://api.example.com", ClientID: "client-1", Email: "a@example.com"}
	idB := Identity{BaseURL: "https://api.example.com", ClientID: "client-2", Email: "a@example.com"}

	if err := Save(idA, "token-a", time.Now().Add(time.Hour), "user-a"); err != nil {
		t.Fatalf("Save A: %v", err)
	}
	if err := Save(idB, "token-b", time.Now().Add(time.Hour), "user-b"); err != nil {
		t.Fatalf("Save B: %v", err)
	}

	if err := Clear(idA); err != nil {
		t.Fatalf("Clear A: %v", err)
	}
	if _, err := Load(idA); err != keyring.ErrKeyNotFound {
		t.Fatalf("expected A cleared, got %v", err)
	}
	if got, err := Load(idB); err != nil || got.Token != "token-b" {
		t.Fatalf("B should remain, got %v err %v", got, err)
	}
}

func TestCacheKeyNormalization(t *testing.T) {
	k1 := cacheKey(Identity{BaseURL: "https://API.example.com/", ClientID: "id", Email: "User@Example.com "})
	k2 := cacheKey(Identity{BaseURL: "https://api.example.com", ClientID: "id", Email: "user@example.com"})
	if k1 != k2 {
		t.Fatalf("cacheKey should normalize; got %q vs %q", k1, k2)
	}
}

func TestCacheKeyHandlesEmptyEmail(t *testing.T) {
	k1 := cacheKey(Identity{BaseURL: "https://api.example.com", ClientID: "id", Email: ""})
	k2 := cacheKey(Identity{BaseURL: "https://api.example.com/", ClientID: "id", Email: " "})
	if k1 != k2 {
		t.Fatalf("cacheKey should normalize empty emails; got %q vs %q", k1, k2)
	}
}

func TestLoadWithoutEmailFindsSingleMatch(t *testing.T) {
	withTestKeyring(t)
	id := Identity{BaseURL: "https://api.example.com", ClientID: "client-1", Email: "user@example.com"}
	if err := Save(id, "tok", time.Now().Add(time.Hour), "user-1"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// email omitted -> should still find the single token
	idNoEmail := Identity{BaseURL: id.BaseURL, ClientID: id.ClientID}
	cached, err := Load(idNoEmail)
	if err != nil {
		t.Fatalf("Load without email: %v", err)
	}
	if cached.Token != "tok" {
		t.Fatalf("token mismatch: %q", cached.Token)
	}
}

func TestLoadWithoutEmailMultipleMatchesFails(t *testing.T) {
	withTestKeyring(t)
	common := Identity{BaseURL: "https://api.example.com", ClientID: "client-1"}
	if err := Save(Identity{BaseURL: common.BaseURL, ClientID: common.ClientID, Email: "a@example.com"}, "ta", time.Now().Add(time.Hour), "ua"); err != nil {
		t.Fatalf("save a: %v", err)
	}
	if err := Save(Identity{BaseURL: common.BaseURL, ClientID: common.ClientID, Email: "b@example.com"}, "tb", time.Now().Add(time.Hour), "ub"); err != nil {
		t.Fatalf("save b: %v", err)
	}
	if _, err := Load(common); err != keyring.ErrKeyNotFound {
		t.Fatalf("expected not found when multiple matches, got %v", err)
	}
}

// unwritableKeyring simulates a backend like the macOS login keychain when the
// current session has no writable keychain: Open and Get succeed, but Set fails.
type unwritableKeyring struct{}

var errUnwritable = errors.New("keyring: write denied")

func (unwritableKeyring) Set(keyring.Item) error { return errUnwritable }
func (unwritableKeyring) Get(string) (keyring.Item, error) {
	return keyring.Item{}, keyring.ErrKeyNotFound
}

func (unwritableKeyring) GetMetadata(string) (keyring.Metadata, error) {
	return keyring.Metadata{}, keyring.ErrKeyNotFound
}
func (unwritableKeyring) Remove(string) error     { return errUnwritable }
func (unwritableKeyring) Keys() ([]string, error) { return nil, nil }

func TestSaveFallsBackToFileWhenPrimarySetFails(t *testing.T) {
	tmp := t.TempDir()

	restorePrimary := SetOpenKeyringForTest(func() (keyring.Keyring, error) {
		return unwritableKeyring{}, nil
	})
	t.Cleanup(restorePrimary)

	restoreFile := SetOpenFileKeyringForTest(func() (keyring.Keyring, error) {
		return keyring.Open(keyring.Config{
			ServiceName:      serviceName + "-test",
			AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
			FileDir:          filepath.Join(tmp, "keyring"),
			FilePasswordFunc: func(_ string) (string, error) { return "test-pass", nil },
		})
	})
	t.Cleanup(restoreFile)

	id := Identity{BaseURL: "https://api.example.com", ClientID: "client-1", Email: "u@example.com"}
	if err := Save(id, "tok", time.Now().Add(time.Hour), "u1"); err != nil {
		t.Fatalf("Save should fall back to file: %v", err)
	}

	got, err := Load(id)
	if err != nil {
		t.Fatalf("Load from file fallback: %v", err)
	}
	if got.Token != "tok" {
		t.Fatalf("token = %q, want tok", got.Token)
	}
}

func TestFilePasswordFunc(t *testing.T) {
	pw, err := filePassword("ignored")
	if err != nil {
		t.Fatalf("filePassword: %v", err)
	}
	if pw != serviceName+"-fallback" {
		t.Fatalf("password = %q, want %q", pw, serviceName+"-fallback")
	}
}

func TestDefaultOpenFileKeyring(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ring, err := defaultOpenFileKeyring()
	if err != nil {
		t.Fatalf("defaultOpenFileKeyring: %v", err)
	}
	item := keyring.Item{Key: "k", Data: []byte("v")}
	if err := ring.Set(item); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := ring.Get("k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Data) != "v" {
		t.Fatalf("data = %q", got.Data)
	}
}

func TestDefaultKeyringTrustsApplication(t *testing.T) {
	config := defaultKeyringConfig()
	if !config.KeychainTrustApplication {
		t.Fatal("default macOS keychain items should trust the calling application")
	}
}

func TestIdentityKeyFromStorageKey(t *testing.T) {
	id := Identity{BaseURL: "https://api.example.com", ClientID: "client", Email: "user@example.com"}
	raw, ok := identityKeyFromStorageKey(storageKey(id))
	if !ok || raw != cacheKey(id) {
		t.Fatalf("decoded = %q ok=%v", raw, ok)
	}
	if raw, ok := identityKeyFromStorageKey(cacheKey(id)); !ok || raw != cacheKey(id) {
		t.Fatalf("legacy decoded = %q ok=%v", raw, ok)
	}
	if _, ok := identityKeyFromStorageKey(storageKeyV2Prefix + "not@base64"); ok {
		t.Fatalf("invalid storage key should fail")
	}
	if _, ok := identityKeyFromStorageKey("other"); ok {
		t.Fatalf("unrelated key should fail")
	}
}

func TestIgnorableLegacyKeyError(t *testing.T) {
	if isIgnorableLegacyKeyError(nil) {
		t.Fatalf("nil should not be ignorable")
	}
	if !isIgnorableLegacyKeyError(&os.PathError{Op: "open", Path: "x", Err: os.ErrNotExist}) {
		t.Fatalf("path error should be ignorable")
	}
	if !isIgnorableLegacyKeyError(errors.New("The filename, directory name, or volume label syntax is incorrect.")) {
		t.Fatalf("windows legacy key error should be ignorable")
	}
	if isIgnorableLegacyKeyError(errors.New("boom")) {
		t.Fatalf("generic error should not be ignorable")
	}
}
