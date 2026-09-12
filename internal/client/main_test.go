package client

import (
	"os"
	"testing"

	"github.com/99designs/keyring"
	"github.com/steipete/eightctl/internal/tokencache"
)

// TestMain keeps this package's tests off the developer's real credential store.
//
// Several tests drive the full authentication path, and a successful
// authentication caches the issued token through tokencache.Save. Without this,
// Save reaches the default opener, which on a cgo-enabled macOS build is the
// login Keychain: running `go test ./...` wrote entries for identities like
// test@example.com into the developer's own Keychain and left them there. A
// released binary is built with CGO_ENABLED=0 and cannot see the Keychain, so
// `eightctl logout` will not clean them up either.
//
// Pointing both openers at in-memory stores for the whole package fixes every
// current test and any later one that reaches the cache without having to
// remember this.
func TestMain(m *testing.M) {
	primary := keyring.NewArrayKeyring(nil)
	file := keyring.NewArrayKeyring(nil)

	restorePrimary := tokencache.SetOpenKeyringForTest(func() (keyring.Keyring, error) {
		return primary, nil
	})
	restoreFile := tokencache.SetOpenFileKeyringForTest(func() (keyring.Keyring, error) {
		return file, nil
	})

	code := m.Run()

	restoreFile()
	restorePrimary()
	os.Exit(code)
}
