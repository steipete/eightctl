package daemon

import (
	"context"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/99designs/keyring"
	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/tokencache"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRunnerCancelsActiveRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ring := keyring.NewArrayKeyring(nil)
		t.Cleanup(tokencache.SetOpenKeyringForTest(func() (keyring.Keyring, error) { return ring, nil }))
		t.Cleanup(tokencache.SetOpenFileKeyringForTest(func() (keyring.Keyring, error) { return ring, nil }))
		c := client.New("fixture", "fixture", "uid", "", "")
		if err := tokencache.Save(c.Identity(), "fixture", time.Now().Add(time.Hour), "uid"); err != nil {
			t.Fatal(err)
		}
		started := make(chan struct{})
		c.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			close(started)
			<-req.Context().Done()
			return nil, req.Context().Err()
		})}
		r := Runner{Client: c, Timezone: time.UTC, Items: []ScheduleItem{{Time: time.Now().UTC().Add(time.Minute).Format("15:04"), Action: "on"}}}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- r.Run(ctx) }()
		synctest.Wait()
		time.Sleep(time.Minute)
		<-started
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("graceful cancellation: %v", err)
		}
	})
}
