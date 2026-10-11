package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steipete/eightctl/internal/alarmguard"
)

// A provider may commit the write before its response becomes unreadable.
// Repeating the command with a fresh Client must not send a second POST.
func TestOneOffCreateUnreadableResponseBlocksNextInvocation(t *testing.T) {
	for _, body := range []string{`{"alarm":`, `{"alarm":"unexpected"}`} {
		t.Run(body, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "attempts")
			posts := 0
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				posts++
				return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			for invocation := 0; invocation < 2; invocation++ {
				c := New("fixture", "fixture", "uid", "", "")
				c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
				c.HTTP = &http.Client{Transport: transport}
				c.alarmAttempts = &alarmguard.Store{Dir: dir}
				_, err := c.CreateOneOffAlarm(context.Background(), OneOffAlarm{Time: "12:00:00", Enabled: true})
				if err == nil || !strings.Contains(err.Error(), "may have succeeded") {
					t.Errorf("invocation %d: need uncertain creation warning, got %v", invocation, err)
				}
			}
			if posts != 1 {
				t.Fatalf("POST count = %d, want 1 across separate invocations", posts)
			}
		})
	}
}

func TestOneOffCreateNeverRetriesFailuresOrMissingIDs(t *testing.T) {
	for _, kind := range []string{"timeout", "401", "429", "missing-id", "null"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "attempts")
			posts := 0
			for invocation := 0; invocation < 2; invocation++ {
				c := New("fixture", "fixture", "uid", "", "")
				c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
				c.alarmAttempts = &alarmguard.Store{Dir: dir}
				c.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					posts++
					if kind == "timeout" {
						return nil, context.DeadlineExceeded
					}
					code, body := http.StatusCreated, `{}`
					if kind == "401" {
						code = http.StatusUnauthorized
					}
					if kind == "429" {
						code = http.StatusTooManyRequests
					}
					if kind == "null" {
						body = `null`
					}
					return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
				})}
				_, err := c.CreateOneOffAlarm(context.Background(), OneOffAlarm{Time: "12:00:00", Enabled: true})
				if err == nil || !strings.Contains(err.Error(), "may have succeeded") {
					t.Fatalf("%s invocation %d: %v", kind, invocation, err)
				}
			}
			if posts != 1 {
				t.Fatalf("POSTs=%d, want 1", posts)
			}
		})
	}
}

func TestOneOffConfirmedRetryReadsExistingAlarmWithoutPosting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	posts, reads := 0, 0
	var firstAttempt string
	for invocation := 0; invocation < 2; invocation++ {
		c := New("fixture", "fixture", "uid", "", "")
		c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
		c.alarmAttempts = &alarmguard.Store{Dir: dir}
		c.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body := `{"alarm":{"id":"created","time":"12:00:00"}}`
			switch req.Method {
			case http.MethodPost:
				posts++
			case http.MethodGet:
				reads++
				body = `{"alarms":[{"id":"created","time":"12:00:00"}]}`
			default:
				t.Fatalf("unexpected method %s", req.Method)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		got, err := c.CreateOneOffAlarm(context.Background(), OneOffAlarm{Time: "12:00:00", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "created" || got.CreationAttempt == "" {
			t.Fatalf("result=%#v", got)
		}
		if invocation == 0 {
			firstAttempt = got.CreationAttempt
		} else if got.CreationAttempt != firstAttempt {
			t.Fatal("retry changed attempt token")
		}
	}
	if posts != 1 || reads != 1 {
		t.Fatalf("POST=%d GET=%d, want 1 each", posts, reads)
	}
}

func TestOneOffCreateDoesNotFollowRedirect(t *testing.T) {
	var posts atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posts.Add(1); io.WriteString(w, `{"id":"duplicate"}`) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c := New("fixture", "fixture", "uid", "", "")
	c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
	c.AppURL = source.URL
	c.HTTP = source.Client()
	c.alarmAttempts = &alarmguard.Store{Dir: filepath.Join(t.TempDir(), "attempts")}
	if _, err := c.CreateOneOffAlarm(context.Background(), OneOffAlarm{Time: "12:00:00"}); err == nil {
		t.Fatal("redirect was treated as confirmed creation")
	}
	if posts.Load() != 1 {
		t.Fatalf("POSTs=%d, want no redirect replay", posts.Load())
	}
}

func TestOneOffAttemptScopesResolvedTargetRatherThanCredentials(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	posts := 0
	for _, tc := range []struct {
		provider, user, credential string
		wantPosts                  int
	}{
		{"https://fixture.invalid", "target-a", "first-credential", 1},
		{"https://fixture.invalid/", "target-a", "different-credential", 1},
		{"https://fixture.invalid", "target-b", "first-credential", 2},
		{"https://other-fixture.invalid", "target-a", "first-credential", 3},
	} {
		c := New(tc.credential, "fixture", tc.user, tc.credential, "")
		c.AppURL = tc.provider
		c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
		c.alarmAttempts = &alarmguard.Store{Dir: dir}
		c.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			posts++
			return nil, context.DeadlineExceeded
		})}
		if _, err := c.CreateOneOffAlarm(context.Background(), OneOffAlarm{Time: "12:00:00"}); err == nil {
			t.Fatal("expected uncertainty")
		}
		if posts != tc.wantPosts {
			t.Fatalf("POSTs=%d, want %d", posts, tc.wantPosts)
		}
	}
}

func TestOneOffExplicitNextAttemptCannotBeRepeated(t *testing.T) {
	c := New("fixture", "fixture", "uid", "", "")
	c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
	c.alarmAttempts = &alarmguard.Store{Dir: filepath.Join(t.TempDir(), "attempts")}
	posts := 0
	c.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", req.Method)
		}
		posts++
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{"id":"created"}`))}, nil
	})}
	alarm := OneOffAlarm{Time: "12:00:00"}
	first, err := c.CreateOneOffAlarm(context.Background(), alarm)
	if err != nil {
		t.Fatal(err)
	}
	alarm.Time = "13:00:00"
	if _, err = c.CreateOneOffAlarm(context.Background(), alarm); err == nil {
		t.Fatal("changed payload must require explicit acknowledgment")
	}
	next, err := c.CreateNextOneOffAlarm(context.Background(), alarm, first.CreationAttempt)
	if err != nil || next.CreationAttempt == first.CreationAttempt {
		t.Fatalf("next creation: %v", err)
	}
	if _, err = c.CreateNextOneOffAlarm(context.Background(), alarm, first.CreationAttempt); err == nil {
		t.Fatal("old token submitted another alarm")
	}
	if posts != 2 {
		t.Fatalf("POSTs=%d, want 2 deliberate creations", posts)
	}
}

func TestOneOffCanceledPreflightDoesNotReserveOrSubmit(t *testing.T) {
	c := New("fixture", "fixture", "uid", "", "")
	c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
	dir := filepath.Join(t.TempDir(), "attempts")
	c.alarmAttempts = &alarmguard.Store{Dir: dir}
	c.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("canceled preflight submitted")
		return nil, context.Canceled
	})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.CreateOneOffAlarm(ctx, OneOffAlarm{Time: "12:00:00"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled preflight created state: %v", err)
	}
}

func TestOneOffCreateGuardAcrossProcessesAndCrashWindows(t *testing.T) {
	if phase := os.Getenv("EIGHTCTL_TEST_CREATE_PHASE"); phase != "" {
		dir := os.Getenv("EIGHTCTL_TEST_CREATE_STATE")
		c := New("fixture", "fixture", "uid", "", "")
		c.token, c.tokenExp = "fixture", time.Now().Add(time.Hour)
		c.alarmAttempts = &alarmguard.Store{Dir: dir}
		c.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if phase == "crash-before-post" {
				os.Exit(23)
			}
			body := `{"alarm":{"id":"created","time":"12:00:00"}}`
			if req.Method == http.MethodPost {
				file, err := os.OpenFile(filepath.Join(dir, "synthetic-posts"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = file.WriteString("POST\n"); err != nil {
					t.Fatal(err)
				}
				if err = file.Close(); err != nil {
					t.Fatal(err)
				}
				if phase == "crash-after-post" {
					os.Exit(23)
				}
				if phase == "held-post" {
					if err := os.WriteFile(filepath.Join(dir, "entered"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
					deadline := time.Now().Add(5 * time.Second)
					for {
						if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("parent did not release fixture")
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
				if phase == "malformed" || phase == "retry-unknown" {
					body = `{"alarm":`
				}
			} else {
				body = `{"alarms":[{"id":"created","time":"12:00:00"}]}`
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		_, err := c.CreateOneOffAlarm(context.Background(), OneOffAlarm{Time: "12:00:00", Enabled: true})
		if phase == "crash-after-confirmation" {
			if err != nil {
				t.Fatal(err)
			}
			os.Exit(23)
		}
		if phase == "retry-unknown" || phase == "malformed" {
			if err == nil {
				t.Fatal("uncertain attempt became successful")
			}
		} else if err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, phase := range []string{"malformed", "crash-before-post", "crash-after-post", "crash-after-confirmation"} {
		t.Run(phase, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "attempts")
			run := func(selected string, crash bool) {
				command := exec.Command(os.Args[0], "-test.run=^TestOneOffCreateGuardAcrossProcessesAndCrashWindows$")
				command.Env = append(os.Environ(), "EIGHTCTL_TEST_CREATE_PHASE="+selected, "EIGHTCTL_TEST_CREATE_STATE="+dir)
				out, err := command.CombinedOutput()
				if crash {
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != 23 {
						t.Fatalf("expected controlled crash: %v %s", err, out)
					}
				} else if err != nil {
					t.Fatalf("child: %v %s", err, out)
				}
			}
			run(phase, strings.HasPrefix(phase, "crash-"))
			retry := "retry-unknown"
			if phase == "crash-after-confirmation" {
				retry = "replay-confirmed"
			}
			run(retry, false)
			data, err := os.ReadFile(filepath.Join(dir, "synthetic-posts"))
			if phase == "crash-before-post" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("no POST expected: %s %v", data, err)
				}
			} else if err != nil || string(data) != "POST\n" {
				t.Fatalf("POST evidence=%q error=%v", data, err)
			}
		})
	}
	t.Run("overlapping processes", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "attempts")
		command := func(phase string) *exec.Cmd {
			c := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestOneOffCreateGuardAcrossProcessesAndCrashWindows$")
			c.Env = append(os.Environ(), "EIGHTCTL_TEST_CREATE_PHASE="+phase, "EIGHTCTL_TEST_CREATE_STATE="+dir)
			return c
		}
		first := command("held-post")
		var output bytes.Buffer
		first.Stdout = &output
		first.Stderr = &output
		if err := first.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = first.Process.Kill() })
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(filepath.Join(dir, "entered")); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("first process did not submit")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if out, err := command("retry-unknown").CombinedOutput(); err != nil {
			t.Fatalf("overlapping attempt: %v %s", err, out)
		}
		if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := first.Wait(); err != nil {
			t.Fatalf("first attempt: %v %s", err, output.Bytes())
		}
		data, err := os.ReadFile(filepath.Join(dir, "synthetic-posts"))
		if err != nil || string(data) != "POST\n" {
			t.Fatalf("POST evidence=%q err=%v", data, err)
		}
	})
}
