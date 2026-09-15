package tokencache

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"charm.land/log/v2"
	"github.com/99designs/keyring"
)

const (
	serviceName        = "eightctl"
	tokenKey           = "oauth-token"
	storageKeyV2Prefix = tokenKey + "_v2_"
)

type CachedToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    string    `json:"user_id,omitempty"`
}

// Identity describes the authentication context a token belongs to.
// Tokens are namespaced by base URL, client ID, and email so switching
// between accounts or environments doesn't reuse the wrong credentials.
type Identity struct {
	BaseURL  string
	ClientID string
	Email    string
}

var (
	openKeyring     = defaultOpenKeyring
	openFileKeyring = defaultOpenFileKeyring

	ErrAmbiguousAccount = errors.New("multiple cached accounts; specify --email")
)

// SetOpenKeyringForTest swaps the keyring opener; it returns a restore func.
// Not safe for concurrent tests; intended for isolated test scenarios.
func SetOpenKeyringForTest(fn func() (keyring.Keyring, error)) (restore func()) {
	prev := openKeyring
	openKeyring = fn
	return func() { openKeyring = prev }
}

// SetOpenFileKeyringForTest swaps the file-backed fallback opener.
// Use with SetOpenKeyringForTest to exercise the fallback path in isolation.
func SetOpenFileKeyringForTest(fn func() (keyring.Keyring, error)) (restore func()) {
	prev := openFileKeyring
	openFileKeyring = fn
	return func() { openFileKeyring = prev }
}

func defaultOpenKeyring() (keyring.Keyring, error) {
	return openBackends(keyring.KeychainBackend, keyring.SecretServiceBackend, keyring.WinCredBackend, keyring.FileBackend)
}

func defaultOpenFileKeyring() (keyring.Keyring, error) {
	return openBackends(keyring.FileBackend)
}

func openBackends(backends ...keyring.BackendType) (keyring.Keyring, error) {
	home, _ := os.UserHomeDir()
	return keyring.Open(keyring.Config{
		ServiceName:      serviceName,
		AllowedBackends:  backends,
		FileDir:          filepath.Join(home, ".config", "eightctl", "keyring"),
		FilePasswordFunc: filePassword,
	})
}

func filePassword(_ string) (string, error) {
	return serviceName + "-fallback", nil
}

func Save(id Identity, token string, expiresAt time.Time, userID string) error {
	data, err := json.Marshal(CachedToken{
		Token:     token,
		ExpiresAt: expiresAt,
		UserID:    userID,
	})
	if err != nil {
		return err
	}
	item := keyring.Item{
		Key:   storageKey(id),
		Label: serviceName + " token",
		Data:  data,
	}

	primaryErr := trySetWith(openKeyring, item)
	if primaryErr == nil {
		log.Debug("keyring saved token")
		return nil
	}
	log.Debug("primary keyring set failed; falling back to file backend", "error", primaryErr)

	if fileErr := trySetWith(openFileKeyring, item); fileErr != nil {
		log.Debug("file keyring set failed", "error", fileErr)
		return primaryErr
	}
	log.Debug("keyring saved token to file fallback")
	return nil
}

func trySetWith(opener func() (keyring.Keyring, error), item keyring.Item) error {
	ring, err := opener()
	if err != nil {
		return err
	}
	return ring.Set(item)
}

// Load returns the cached token for the given Identity, if present and unexpired.
// Tokens are namespaced by Identity (base URL + client ID + email) — not by
// UserID — because a single OAuth principal (email) can legitimately act on
// multiple household userIDs. The cached UserID is informational metadata for
// callers that want to recover "which userID was primary at auth time."
func Load(id Identity) (*CachedToken, error) {
	rings, err := openStores()
	if err != nil {
		return nil, err
	}
	id, err = resolveIdentity(rings, id)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, ring := range rings {
		cached, err := loadFrom(ring, id)
		if err == nil {
			return cached, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

func loadFrom(ring keyring.Keyring, id Identity) (*CachedToken, error) {
	key := storageKey(id)
	item, err := ring.Get(key)
	if err == keyring.ErrKeyNotFound {
		legacyKey := cacheKey(id)
		item, err = ring.Get(legacyKey)
		if err == nil {
			key = legacyKey
		} else if isIgnorableLegacyKeyError(err) {
			err = keyring.ErrKeyNotFound
		}
	}
	if err != nil {
		return nil, err
	}
	var cached CachedToken
	if err := json.Unmarshal(item.Data, &cached); err != nil {
		return nil, err
	}
	if time.Now().After(cached.ExpiresAt) {
		_ = ring.Remove(key)
		return nil, keyring.ErrKeyNotFound
	}
	return &cached, nil
}

// Clear removes the identity's local token cache from reachable backends.
// An unavailable backend is tolerated if another opens, but removal failures
// from an opened backend are returned. This does not revoke tokens at the service.
func Clear(id Identity) error {
	rings, err := openStores()
	if err != nil {
		return err
	}
	id, err = resolveIdentity(rings, id)
	if err != nil {
		return err
	}
	var removalErrors []error
	for _, ring := range rings {
		if err := clearFrom(ring, id); err != nil {
			removalErrors = append(removalErrors, err)
		}
	}
	return errors.Join(removalErrors...)
}

func openStores() ([]keyring.Keyring, error) {
	var rings []keyring.Keyring
	var openErrors []error
	for _, opener := range []func() (keyring.Keyring, error){openKeyring, openFileKeyring} {
		ring, err := opener()
		if err != nil {
			openErrors = append(openErrors, err)
		} else {
			rings = append(rings, ring)
		}
	}
	if len(rings) == 0 {
		return nil, errors.Join(openErrors...)
	}
	return rings, nil
}

// Resolve omitted emails across all reachable stores before reading or deleting
// any token, so a primary-store hit cannot conceal another cached account.
func resolveIdentity(rings []keyring.Keyring, id Identity) (Identity, error) {
	if strings.TrimSpace(id.Email) == "" {
		identities := map[string]struct{}{}
		for _, ring := range rings {
			matches, err := keysForClient(ring, id)
			if err != nil {
				return id, err
			}
			for identity := range matches {
				identities[identity] = struct{}{}
			}
		}
		if len(identities) > 1 {
			return id, ErrAmbiguousAccount
		}
		for identity := range identities {
			id.Email = strings.TrimPrefix(identity, clientKeyPrefix(id))
		}
	}
	return id, nil
}

func clearFrom(ring keyring.Keyring, id Identity) error {
	for i, key := range []string{storageKey(id), cacheKey(id)} {
		if err := ring.Remove(key); err != nil && !isAbsentOrUnnameable(err, i == 1) {
			return err
		}
	}
	return nil
}

func isAbsentOrUnnameable(err error, legacy bool) bool {
	if errors.Is(err, keyring.ErrKeyNotFound) || errors.Is(err, fs.ErrNotExist) {
		return true
	}
	// Only legacy keys can contain Windows-invalid filename characters. Other
	// PathErrors (permissions, read-only mounts, I/O failures) may leave a token.
	const windowsInvalidName syscall.Errno = 123
	return legacy && runtime.GOOS == "windows" && errors.Is(err, windowsInvalidName)
}

func cacheKey(id Identity) string {
	base := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(id.BaseURL)), "/")
	email := strings.ToLower(strings.TrimSpace(id.Email))
	return tokenKey + ":" + base + "|" + id.ClientID + "|" + email
}

func storageKey(id Identity) string {
	return storageKeyV2Prefix + base64.RawURLEncoding.EncodeToString([]byte(cacheKey(id)))
}

func identityKeyFromStorageKey(key string) (string, bool) {
	if strings.HasPrefix(key, storageKeyV2Prefix) {
		raw := strings.TrimPrefix(key, storageKeyV2Prefix)
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return "", false
		}
		return string(decoded), true
	}
	if strings.HasPrefix(key, tokenKey+":") {
		return key, true
	}
	return "", false
}

func isIgnorableLegacyKeyError(err error) bool {
	if err == nil {
		return false
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "filename, directory name, or volume label syntax is incorrect")
}

func clientKeyPrefix(id Identity) string {
	id.Email = ""
	return cacheKey(id)
}

// Group legacy and current storage keys by account, preferring the current key.
func keysForClient(ring keyring.Keyring, id Identity) (map[string]string, error) {
	keys, err := ring.Keys()
	if err != nil {
		return nil, err
	}
	matches := map[string]string{}
	prefix := clientKeyPrefix(id)
	for _, key := range keys {
		identity, ok := identityKeyFromStorageKey(key)
		if !ok || !strings.HasPrefix(identity, prefix) {
			continue
		}
		if _, exists := matches[identity]; !exists || strings.HasPrefix(key, storageKeyV2Prefix) {
			matches[identity] = key
		}
	}
	return matches, nil
}
