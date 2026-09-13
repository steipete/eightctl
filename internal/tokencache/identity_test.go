package tokencache

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/99designs/keyring"
)

func TestClearWithoutEmailRemovesSelectedAccount(t *testing.T) {
	primary, fallback := keyring.NewArrayKeyring(nil), keyring.NewArrayKeyring(nil)
	t.Cleanup(SetOpenKeyringForTest(func() (keyring.Keyring, error) { return primary, nil }))
	t.Cleanup(SetOpenFileKeyringForTest(func() (keyring.Keyring, error) { return fallback, nil }))
	id := Identity{BaseURL: "https://fixture.invalid", ClientID: "fixture", Email: "user@example.invalid"}
	if err := Save(id, "fixture", time.Now().Add(time.Hour), "uid"); err != nil {
		t.Fatal(err)
	}
	withoutEmail := id
	withoutEmail.Email = ""
	if _, err := Load(withoutEmail); err != nil {
		t.Fatal(err)
	}
	if err := Clear(withoutEmail); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(id); err == nil {
		t.Fatal("logout left the selected account usable")
	}
}

func TestClearWithoutEmailRejectsAmbiguityAcrossStores(t *testing.T) {
	primary, fallback := keyring.NewArrayKeyring(nil), keyring.NewArrayKeyring(nil)
	t.Cleanup(SetOpenKeyringForTest(func() (keyring.Keyring, error) { return primary, nil }))
	t.Cleanup(SetOpenFileKeyringForTest(func() (keyring.Keyring, error) { return fallback, nil }))
	id := Identity{BaseURL: "https://fixture.invalid", ClientID: "fixture"}
	for i, ring := range []keyring.Keyring{primary, fallback} {
		account := id
		account.Email = []string{"one@example.invalid", "two@example.invalid"}[i]
		if err := ring.Set(keyring.Item{Key: storageKey(account), Data: []byte("fixture")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := Clear(id); err == nil {
		t.Fatal("ambiguous logout reported success")
	}
	for _, ring := range []keyring.Keyring{primary, fallback} {
		keys, err := ring.Keys()
		if err != nil || len(keys) != 1 {
			t.Fatalf("ambiguous logout changed a store: %v %v", keys, err)
		}
	}
}

func TestLegacyAndCurrentKeysAreOneAccount(t *testing.T) {
	ring := keyring.NewArrayKeyring(nil)
	t.Cleanup(SetOpenKeyringForTest(func() (keyring.Keyring, error) { return ring, nil }))
	t.Cleanup(SetOpenFileKeyringForTest(func() (keyring.Keyring, error) { return ring, nil }))
	id := Identity{BaseURL: "https://fixture.invalid", ClientID: "fixture", Email: "user@example.invalid"}
	if err := Save(id, "current", time.Now().Add(time.Hour), "uid"); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(CachedToken{Token: "legacy", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Set(keyring.Item{Key: cacheKey(id), Data: data}); err != nil {
		t.Fatal(err)
	}
	id.Email = ""
	got, err := Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "current" {
		t.Fatal("did not prefer current cache key")
	}
	if err := Clear(id); err != nil {
		t.Fatal(err)
	}
	keys, err := ring.Keys()
	if err != nil || len(keys) != 0 {
		t.Fatalf("logout left keys: %v %v", keys, err)
	}
}
