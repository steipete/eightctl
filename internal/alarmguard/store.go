// Package alarmguard prevents retransmission of a one-off alarm creation on a
// shared local state directory. It makes no provider idempotency guarantee.
package alarmguard

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Store must use the same private directory for all processes controlling a target.
type Store struct{ Dir string }

type Receipt struct {
	Version     int    `json:"version"`
	Attempt     string `json:"attempt"`
	RequestHash string `json:"request_hash"`
	State       string `json:"state"`
	AlarmID     string `json:"alarm_id,omitempty"`
}

// UncertainError deliberately excludes raw provider responses from its text.
// The underlying cause remains available through errors.Is/As.
type UncertainError struct {
	Attempt string
	Cause   error
}

func (e *UncertainError) Error() string {
	return fmt.Sprintf("alarm creation may have succeeded; attempt %s is blocked: inspect the official app before retrying; unresolved attempts are never automatically reset", e.Attempt)
}
func (e *UncertainError) Unwrap() error { return e.Cause }

func Default() (Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Store{}, err
	}
	return Store{Dir: filepath.Join(home, ".config", "eightctl", "alarm-attempts")}, nil
}

// Scope uses the provider and resolved target user, independent of credential
// aliases or selected OAuth clients, so these cannot bypass the same target guard.
func Scope(provider, user string) string {
	data, _ := json.Marshal([]string{strings.TrimRight(provider, "/"), user})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// Run reserves and durably records an attempt before submit. Confirmed attempts
// replay without submitting. A deliberate next creation needs the preceding
// confirmed attempt token. Pending attempts block every request and token.
func (s Store) Run(scope string, request []byte, after string, submit func() (string, error)) (receipt Receipt, reused bool, err error) {
	return s.run(scope, request, after, submit, writeReceipt)
}

func (s Store) run(scope string, request []byte, after string, submit func() (string, error), persist func(*os.Root, string, Receipt) error) (receipt Receipt, reused bool, err error) {
	if !validHex(scope, 32) {
		return Receipt{}, false, errors.New("invalid alarm target scope")
	}
	if err = os.MkdirAll(s.Dir, 0o700); err != nil {
		return Receipt{}, false, fmt.Errorf("prepare alarm attempt state: %w", err)
	}
	info, err := os.Lstat(s.Dir)
	if err != nil {
		return Receipt{}, false, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return Receipt{}, false, errors.New("alarm attempt directory must be a private, non-symlink directory (0700)")
	}
	// Persist ancestor directory entries too: on first use, syncing a receipt
	// inside a newly created directory alone does not persist its parent entry.
	for parent := filepath.Dir(filepath.Clean(s.Dir)); ; parent = filepath.Dir(parent) {
		directory, openErr := os.Open(parent)
		if openErr != nil {
			return Receipt{}, false, openErr
		}
		if syncErr := errors.Join(directory.Sync(), directory.Close()); syncErr != nil {
			return Receipt{}, false, fmt.Errorf("cannot persist alarm attempt directory: %w", syncErr)
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	root, err := os.OpenRoot(s.Dir)
	if err != nil {
		return Receipt{}, false, err
	}
	defer root.Close()
	lock := scope + ".lock"
	if err = root.Mkdir(lock, 0o700); err != nil {
		return Receipt{}, false, errors.New("alarm creation is locked by another process or an interrupted attempt; inspect the official app; stale locks are never automatically removed")
	}
	releaseLock := true
	defer func() {
		if !releaseLock {
			return
		}
		if releaseErr := root.Remove(lock); releaseErr != nil && err == nil {
			err = &UncertainError{Attempt: receipt.Attempt, Cause: releaseErr}
		}
	}()
	name := scope + ".json"
	existing, found, err := readReceipt(root, name)
	if err != nil {
		return Receipt{}, false, fmt.Errorf("alarm attempt state is unreadable; creation blocked: %w", err)
	}
	digest := sha256.Sum256(request)
	fingerprint := hex.EncodeToString(digest[:])
	if found {
		if existing.State != "confirmed" {
			return existing, false, &UncertainError{Attempt: existing.Attempt}
		}
		if after == "" {
			if fingerprint != existing.RequestHash {
				return existing, false, errors.New("a previous creation is recorded; use --after-attempt with its confirmed token only to intentionally create a different alarm")
			}
			return existing, true, nil
		}
		if after != existing.Attempt {
			return existing, false, errors.New("--after-attempt does not match the latest confirmed creation; no alarm submitted")
		}
	} else if after != "" {
		return Receipt{}, false, errors.New("no confirmed creation matches --after-attempt; no alarm submitted")
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return Receipt{}, false, err
	}
	receipt = Receipt{Version: 1, Attempt: hex.EncodeToString(token), RequestHash: fingerprint, State: "pending"}
	if err = persist(root, name, receipt); err != nil {
		return receipt, false, fmt.Errorf("cannot durably reserve alarm creation; no alarm submitted: %w", err)
	}
	id, submitErr := submit()
	if submitErr != nil {
		return receipt, false, &UncertainError{Attempt: receipt.Attempt, Cause: submitErr}
	}
	if id == "" || len(id) > 1024 {
		return receipt, false, &UncertainError{Attempt: receipt.Attempt, Cause: errors.New("create response did not include a usable alarm ID")}
	}
	receipt.State, receipt.AlarmID = "confirmed", id
	if err = persist(root, name, receipt); err != nil {
		// Rename may already have exposed confirmed state before sync fails.
		// Retain the previously persisted lock so that even an acknowledgment
		// cannot unlock a receipt whose durable confirmation is uncertain.
		releaseLock = false
		return receipt, false, &UncertainError{Attempt: receipt.Attempt, Cause: err}
	}
	return receipt, false, nil
}

func readReceipt(root *os.Root, name string) (Receipt, bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
		return Receipt{}, false, errors.New("receipt must be a private regular file (0600)")
	}
	file, err := root.Open(name)
	if err != nil {
		return Receipt{}, false, err
	}
	defer file.Close()
	var receipt Receipt
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&receipt); err != nil {
		return Receipt{}, false, err
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return Receipt{}, false, errors.New("invalid trailing receipt data")
	}
	if receipt.Version != 1 || !validHex(receipt.Attempt, 16) || !validHex(receipt.RequestHash, 32) || (receipt.State != "pending" && receipt.State != "confirmed") || (receipt.State == "confirmed" && (receipt.AlarmID == "" || len(receipt.AlarmID) > 1024)) || (receipt.State == "pending" && receipt.AlarmID != "") {
		return Receipt{}, false, errors.New("invalid alarm creation receipt")
	}
	return receipt, true, nil
}

func writeReceipt(root *os.Root, name string, receipt Receipt) error {
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	temporary := name + "." + receipt.Attempt + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer root.Remove(temporary)
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err = root.Rename(temporary, name); err != nil {
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	return errors.Join(syncErr, directory.Close())
}

func validHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && len(value) == size*2
}
