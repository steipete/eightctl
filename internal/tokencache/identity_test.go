package tokencache

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/99designs/keyring"
)

func TestLoadWithoutEmailChecksAllStores(t *testing.T) {
	for _, emails := range [][2]string{
		{"one@example.invalid", "two@example.invalid"},
		{"", "two@example.invalid"},
		{"one@example.invalid", "one@example.invalid"},
	} {
		t.Run(fmt.Sprint(emails), func(t *testing.T) {
			primary, fallback := keyring.NewArrayKeyring(nil), keyring.NewArrayKeyring(nil)
			t.Cleanup(SetOpenKeyringForTest(func() (keyring.Keyring, error) { return primary, nil }))
			t.Cleanup(SetOpenFileKeyringForTest(func() (keyring.Keyring, error) { return fallback, nil }))
			id := Identity{BaseURL: "https://fixture.invalid", ClientID: "fixture"}
			for i, ring := range []keyring.Keyring{primary, fallback} {
				account := id
				account.Email = emails[i]
				data, err := json.Marshal(CachedToken{Token: "fixture", ExpiresAt: time.Now().Add(time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				if err := ring.Set(keyring.Item{Key: storageKey(account), Data: data}); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Load(id)
			if emails[0] != emails[1] {
				if !errors.Is(err, ErrAmbiguousAccount) || got != nil {
					t.Fatal("ambiguous cached accounts silently selected a token")
				}
			} else if err != nil || got == nil {
				t.Fatalf("same account in both stores must remain usable: %v", err)
			}
			id.Email = "two@example.invalid"
			if emails[1] == id.Email {
				if got, err := Load(id); err != nil || got == nil {
					t.Fatalf("explicit account selection failed: %v", err)
				}
			}
		})
	}
}

type unlistableKeyring struct{ keyring.Keyring }

func (unlistableKeyring) Keys() ([]string, error) { return nil, errors.New("fixture list denied") }

func TestLoadWithoutEmailRequiresCompleteAccountLookup(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(fmt.Sprint(unavailable), func(t *testing.T) {
			primary, fallback := keyring.NewArrayKeyring(nil), keyring.NewArrayKeyring(nil)
			t.Cleanup(SetOpenKeyringForTest(func() (keyring.Keyring, error) { return primary, nil }))
			t.Cleanup(SetOpenFileKeyringForTest(func() (keyring.Keyring, error) {
				if unavailable {
					return nil, errors.New("fixture unavailable")
				}
				return unlistableKeyring{fallback}, nil
			}))
			id := Identity{BaseURL: "https://fixture.invalid", ClientID: "fixture", Email: "one@example.invalid"}
			if err := Save(id, "fixture", time.Now().Add(time.Hour), "uid"); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(id); err != nil {
				t.Fatalf("explicit email must not require listing accounts: %v", err)
			}
			id.Email = " "
			_, err := Load(id)
			if unavailable && err != nil {
				t.Fatalf("unavailable fallback should remain tolerated: %v", err)
			}
			if !unavailable && err == nil {
				t.Fatal("selected an account despite failed enumeration of a reachable store")
			}
		})
	}
}

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
