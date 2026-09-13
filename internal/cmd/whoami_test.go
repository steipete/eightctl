package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/tokencache"
)

func TestWhoamiUsesResolvedIdentity(t *testing.T) {
	mode := os.Getenv("EIGHTCTL_TEST_WHOAMI")
	if mode == "" {
		for _, mode := range []string{"cached", "configured"} {
			command := exec.Command(os.Args[0], "-test.run=^TestWhoamiUsesResolvedIdentity$")
			for _, variable := range os.Environ() {
				if !strings.HasPrefix(variable, "EIGHTCTL_") {
					command.Env = append(command.Env, variable)
				}
			}
			command.Env = append(command.Env, "EIGHTCTL_TEST_WHOAMI="+mode)
			if out, err := command.CombinedOutput(); err != nil {
				t.Errorf("%s whoami: %v\n%s", mode, err, out)
			}
		}
		return
	}
	useTempKeyring(t)
	resetViper(t)
	if mode == "cached" {
		c := client.New("", "", "", "", "")
		if err := tokencache.Save(c.Identity(), "fixture", time.Now().Add(time.Hour), "cached-user"); err != nil {
			t.Fatal(err)
		}
	} else {
		viper.Set("user_id", "configured-user")
	}
	requests := make(chan struct{}, 4)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}
		http.Error(w, "unexpected provider request blocked", http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	text, err := captureAwayStatus(t, func() error { return whoamiCmd.RunE(whoamiCmd, nil) })
	if err != nil || text != "UserID: "+mode+"-user\n" || len(requests) != 0 {
		t.Fatalf("output=%q error=%v requests=%d", text, err, len(requests))
	}
}
