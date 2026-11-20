package alarmguard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPendingAttemptBlocksAllPayloadsAndAcknowledgments(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "state")}
	scope := Scope("https://fixture.invalid", "selected-user")
	calls := 0
	r, _, err := s.Run(scope, []byte("first"), "", func() (string, error) { calls++; return "", errors.New("unreadable response") })
	var uncertain *UncertainError
	if !errors.As(err, &uncertain) {
		t.Fatalf("expected uncertain creation, got %v", err)
	}
	for _, payload := range []string{"first", "changed"} {
		_, _, err = s.Run(scope, []byte(payload), r.Attempt, func() (string, error) { calls++; return "duplicate", nil })
		if err == nil {
			t.Fatal("pending attempt was unlocked")
		}
	}
	if calls != 1 {
		t.Fatalf("submissions=%d, want 1", calls)
	}
}

func TestConfirmedAttemptReplaysAndRequiresSingleUseAcknowledgment(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "state")}
	scope := Scope("provider", "user")
	calls := 0
	submit := func() (string, error) { calls++; return "created", nil }
	first, reused, err := s.Run(scope, []byte("same"), "", submit)
	if err != nil || reused {
		t.Fatalf("initial: reused=%v err=%v", reused, err)
	}
	replay, reused, err := s.Run(scope, []byte("same"), "", submit)
	if err != nil || !reused || replay.Attempt != first.Attempt {
		t.Fatalf("replay: %v %v", reused, err)
	}
	if _, _, err = s.Run(scope, []byte("changed"), "", submit); err == nil {
		t.Fatal("changed payload silently created another alarm")
	}
	next, _, err := s.Run(scope, []byte("next"), first.Attempt, submit)
	if err != nil || next.Attempt == first.Attempt {
		t.Fatalf("intentional next: %v", err)
	}
	if _, _, err = s.Run(scope, []byte("next"), first.Attempt, submit); err == nil {
		t.Fatal("acknowledgment was reusable")
	}
	if calls != 2 {
		t.Fatalf("submissions=%d, want 2", calls)
	}
}

func TestConcurrentReservationsShareExclusiveLock(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "state")}
	scope := Scope("provider", "user")
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var wg sync.WaitGroup
	result := make(chan error, 1)
	wg.Go(func() {
		_, _, err := s.Run(scope, []byte("request"), "", func() (string, error) { calls.Add(1); close(entered); <-release; return "id", nil })
		result <- err
	})
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("reservation failed: %v", err)
	}
	if _, _, err := s.Run(scope, []byte("request"), "", func() (string, error) { calls.Add(1); return "duplicate", nil }); err == nil {
		t.Fatal("concurrent reservation succeeded")
	}
	close(release)
	wg.Wait()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("submissions=%d", calls.Load())
	}
}

func TestPrivateStateAndCorruptOrInsecureStateFailClosed(t *testing.T) {
	for _, kind := range []string{"corrupt", "insecure", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			s := Store{Dir: dir}
			scope := Scope("private-provider", "private-user")
			_, _, err := s.Run(scope, []byte("private schedule"), "", func() (string, error) { return "synthetic-alarm", nil })
			if err != nil {
				t.Fatal(err)
			}
			info, _ := os.Stat(dir)
			if info.Mode().Perm() != 0o700 {
				t.Fatal("state directory must be private")
			}
			path := filepath.Join(dir, scope+".json")
			info, _ = os.Stat(path)
			if info.Mode().Perm() != 0o600 {
				t.Fatal("receipt must be private")
			}
			data, _ := os.ReadFile(path)
			for _, secret := range []string{"private-provider", "private-user", "private schedule"} {
				if strings.Contains(string(data), secret) {
					t.Fatal("receipt leaked scope or request")
				}
			}
			switch kind {
			case "corrupt":
				if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "insecure":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".real", path); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			if _, _, err := s.Run(scope, []byte("private schedule"), "", func() (string, error) { called = true; return "duplicate", nil }); err == nil || called {
				t.Fatal("invalid receipt allowed submission")
			}
		})
	}
}

func TestUnusableStorageDoesNotSubmit(t *testing.T) {
	for _, kind := range []string{"insecure-directory", "file", "symlink", "invalid-scope", "unmatched-token"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			scope, after := Scope("provider", "user"), ""
			switch kind {
			case "insecure-directory":
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(dir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(t.TempDir(), dir); err != nil {
					t.Fatal(err)
				}
			case "invalid-scope":
				scope = "../outside"
			case "unmatched-token":
				after = "unknown"
			}
			called := false
			_, _, err := (Store{Dir: dir}).Run(scope, nil, after, func() (string, error) { called = true; return "id", nil })
			if err == nil || called {
				t.Fatalf("unsafe reservation: called=%v error=%v", called, err)
			}
		})
	}
}

func TestUncertainErrorRedactsCauseAndKeepsErrorIdentity(t *testing.T) {
	cause := errors.New("private-account-response")
	err := &UncertainError{Attempt: "synthetic-attempt", Cause: cause}
	if strings.Contains(err.Error(), cause.Error()) || !errors.Is(err, cause) {
		t.Fatal("uncertain error must hide private cause text and preserve error identity")
	}
}

func TestConfirmationStorageFailureRetainsLockEvenWhenConfirmedReceiptIsVisible(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "state")}
	scope := Scope("provider", "user")
	storageFailure := errors.New("synthetic directory sync failure after rename")
	posts := 0
	persist := func(root *os.Root, name string, receipt Receipt) error {
		if err := writeReceipt(root, name, receipt); err != nil {
			return err
		}
		if receipt.State == "confirmed" {
			return storageFailure
		}
		return nil
	}
	receipt, _, err := s.run(scope, []byte("request"), "", func() (string, error) { posts++; return "created", nil }, persist)
	if !errors.Is(err, storageFailure) {
		t.Fatalf("got %v", err)
	}
	root, err := os.OpenRoot(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	visible, found, err := readReceipt(root, scope+".json")
	if err != nil || !found || visible.State != "confirmed" {
		t.Fatalf("fault fixture must leave confirmed receipt visible: found=%v err=%v", found, err)
	}
	for _, after := range []string{receipt.Attempt, ""} {
		_, _, err := s.Run(scope, []byte("request"), after, func() (string, error) { posts++; return "duplicate", nil })
		if err == nil {
			t.Fatal("uncertain durable confirmation allowed another creation")
		}
	}
	if posts != 1 {
		t.Fatalf("POSTs=%d, want 1", posts)
	}
}
