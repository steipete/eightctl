package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/steipete/eightctl/internal/client"
)

// ScheduleItem describes a timed action.
type ScheduleItem struct {
	Time        string `mapstructure:"time" yaml:"time"`
	Action      string `mapstructure:"action" yaml:"action"`
	Temperature string `mapstructure:"temperature" yaml:"temperature"`
}

// Runner executes scheduled items.
type Runner struct {
	Items    []ScheduleItem
	Client   *client.Client
	Timezone *time.Location
	DryRun   bool
	Sync     bool
	PIDFile  string
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.writePID(); err != nil {
		return err
	}
	defer r.removePID()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	executed := map[string]bool{}
	day := time.Now().Day()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sig:
			return nil
		case now := <-ticker.C:
			if now.Day() != day {
				executed = map[string]bool{}
				day = now.Day()
			}
			if err := r.process(now, executed); err != nil {
				return err
			}
		}
	}
}

func (r *Runner) process(now time.Time, executed map[string]bool) error {
	// Ticker timestamps use the host zone; schedules use their configured date.
	now = now.In(r.Timezone)
	for _, item := range r.Items {
		t, err := time.ParseInLocation("15:04", item.Time, r.Timezone)
		if err != nil {
			return fmt.Errorf("parse time %s: %w", item.Time, err)
		}
		candidate := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, r.Timezone)
		if now.Before(candidate) || now.Sub(candidate) >= time.Minute {
			continue
		}
		key := candidate.Format("2006-01-02 15:04") + item.Action
		if executed[key] {
			continue
		}
		executed[key] = true
		if r.DryRun {
			fmt.Printf("DRY-RUN %s %s %s\n", candidate.Format(time.RFC3339), item.Action, item.Temperature)
			continue
		}
		switch item.Action {
		case "on":
			if err := r.Client.TurnOn(context.Background()); err != nil {
				return err
			}
		case "off":
			if err := r.Client.TurnOff(context.Background()); err != nil {
				return err
			}
		case "temp":
			level, err := ParseTemp(item.Temperature)
			if err != nil {
				return err
			}
			if err := r.Client.SetTemperature(context.Background(), level); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown action %s", item.Action)
		}
	}
	return nil
}

func (r *Runner) writePID() error {
	if r.PIDFile == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.PIDFile), 0o755); err != nil {
		return err
	}
	if data, err := os.ReadFile(r.PIDFile); err == nil {
		pid := strings.TrimSpace(string(data))
		if pid != "" {
			return fmt.Errorf("daemon already running (pid %s)", pid)
		}
	}
	return os.WriteFile(r.PIDFile, []byte(fmt.Sprint(os.Getpid())), 0o600)
}

func (r *Runner) removePID() {
	if r.PIDFile != "" {
		_ = os.Remove(r.PIDFile)
	}
}

// parseTempLevel converts "68F" or "20C" to heating level approximation.
// ParseTemp converts user input temperature string to heating level.
func ParseTemp(s string) (int, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if strings.HasSuffix(s, "F") {
		v := strings.TrimSuffix(s, "F")
		var f float64
		_, err := fmt.Sscanf(v, "%f", &f)
		if err != nil {
			return 0, err
		}
		return mapFtoLevel(f), nil
	}
	if strings.HasSuffix(s, "C") {
		v := strings.TrimSuffix(s, "C")
		var c float64
		_, err := fmt.Sscanf(v, "%f", &c)
		if err != nil {
			return 0, err
		}
		return mapCtoLevel(c), nil
	}
	var lvl int
	if _, err := fmt.Sscanf(s, "%d", &lvl); err == nil {
		return lvl, nil
	}
	return 0, fmt.Errorf("temperature must end with F/C or be level")
}

// Simple linear approximations; Eight Sleep internals are non-linear, but this keeps UX consistent.
func mapFtoLevel(f float64) int {
	// Rough map 55F -> -100, 100F -> 100.
	scaled := (f-55)/(100-55)*200 - 100
	if scaled < -100 {
		scaled = -100
	}
	if scaled > 100 {
		scaled = 100
	}
	return int(scaled)
}

func mapCtoLevel(c float64) int {
	// 13C ~ 55F, 38C ~ 100F
	scaled := (c-13)/(38-13)*200 - 100
	if scaled < -100 {
		scaled = -100
	}
	if scaled > 100 {
		scaled = 100
	}
	return int(scaled)
}
