package tokencache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/99designs/keyring"
	"github.com/charmbracelet/log"
)

const (
	serviceName = "eightctl"
	tokenKey    = "oauth-token"
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
	// cachedRing holds the singleton keyring instance.
	// Opening the keyring once and reusing it avoids repeated file system
	// operations and potential issues with concurrent access.
	cachedRing   keyring.Keyring
	cachedRingMu sync.Mutex
	openKeyring  = defaultOpenKeyring
)

// SetOpenKeyringForTest swaps the keyring opener; it returns a restore func.
// Not safe for concurrent tests; intended for isolated test scenarios.
func SetOpenKeyringForTest(fn func() (keyring.Keyring, error)) (restore func()) {
	cachedRingMu.Lock()
	defer cachedRingMu.Unlock()
	prev := openKeyring
	prevRing := cachedRing
	openKeyring = fn
	cachedRing = nil // Clear cache so test opener is used
	return func() {
		cachedRingMu.Lock()
		defer cachedRingMu.Unlock()
		openKeyring = prev
		cachedRing = prevRing
	}
}

func defaultOpenKeyring() (keyring.Keyring, error) {
	cachedRingMu.Lock()
	defer cachedRingMu.Unlock()

	if cachedRing != nil {
		return cachedRing, nil
	}

	home, _ := os.UserHomeDir()
	ring, err := keyring.Open(keyring.Config{
		ServiceName: serviceName,
		// Use FileBackend only. The macOS Keychain backend has issues with
		// adhoc-signed Go binaries: Set() succeeds but the item cannot be
		// retrieved by Get() due to code signature/ACL problems.
		AllowedBackends: []keyring.BackendType{
			keyring.FileBackend,
		},
		FileDir:          filepath.Join(home, ".config", "eightctl", "keyring"),
		FilePasswordFunc: filePassword,
	})
	if err != nil {
		return nil, err
	}
	cachedRing = ring
	return cachedRing, nil
}

func filePassword(_ string) (string, error) {
	return serviceName + "-fallback", nil
}

func Save(id Identity, token string, expiresAt time.Time, userID string) error {
	ring, err := openKeyring()
	if err != nil {
		log.Debug("keyring open failed (save)", "error", err)
		return err
	}
	data, err := json.Marshal(CachedToken{
		Token:     token,
		ExpiresAt: expiresAt,
		UserID:    userID,
	})
	if err != nil {
		return err
	}
	if err := ring.Set(keyring.Item{
		Key:   cacheKey(id),
		Label: serviceName + " token",
		Data:  data,
	}); err != nil {
		log.Debug("keyring set failed", "error", err)
		return err
	}
	log.Debug("keyring saved token")
	return nil
}

func Load(id Identity, expectedUserID string) (*CachedToken, error) {
	ring, err := openKeyring()
	if err != nil {
		log.Debug("keyring open failed (load)", "error", err)
		return nil, err
	}
	key := cacheKey(id)
	item, err := ring.Get(key)
	if err == keyring.ErrKeyNotFound && id.Email == "" {
		// No email specified: attempt to find a single matching token for this base/client.
		if alt, findErr := findSingleForClient(ring, id); findErr == nil {
			key = alt
			item, err = ring.Get(key)
		} else {
			log.Debug("keyring wildcard lookup failed", "error", findErr)
		}
	}
	if err != nil {
		log.Debug("keyring get failed", "error", err)
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
	if expectedUserID != "" && cached.UserID != "" && cached.UserID != expectedUserID {
		return nil, keyring.ErrKeyNotFound
	}
	return &cached, nil
}

func Clear(id Identity) error {
	ring, err := openKeyring()
	if err != nil {
		return err
	}
	key := cacheKey(id)
	if err := ring.Remove(key); err != nil {
		if err == keyring.ErrKeyNotFound || os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

func cacheKey(id Identity) string {
	base := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(id.BaseURL)), "/")
	email := strings.ToLower(strings.TrimSpace(id.Email))
	return tokenKey + ":" + base + "|" + id.ClientID + "|" + email
}

// findSingleForClient finds a single cached key for the given base/client when email is unknown.
// Returns ErrKeyNotFound if none or multiple exist.
func findSingleForClient(ring keyring.Keyring, id Identity) (string, error) {
	keys, err := ring.Keys()
	if err != nil {
		return "", err
	}
	prefix := tokenKey + ":" + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(id.BaseURL)), "/") + "|" + id.ClientID + "|"
	matches := []string{}
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			matches = append(matches, k)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	return "", keyring.ErrKeyNotFound
}
