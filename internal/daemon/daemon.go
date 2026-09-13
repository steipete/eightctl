package daemon

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	items, err := prepareSchedule(r.Items)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	if r.Timezone == nil {
		r.Timezone = time.Local
	}
	if err := r.writePID(); err != nil {
		return err
	}
	defer r.removePID()
	fmt.Printf("daemon started with %d items\n", len(items))

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	executed := map[string]bool{}
	day := time.Now().In(r.Timezone).Format(time.DateOnly)

	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			if date := now.In(r.Timezone).Format(time.DateOnly); date != day {
				executed = map[string]bool{}
				day = date
			}
			if err := r.process(ctx, now, executed, items); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}

func (r *Runner) process(ctx context.Context, now time.Time, executed map[string]bool, items []timedAction) error {
	// Ticker timestamps use the host zone; schedules use their configured date.
	now = now.In(r.Timezone)
	for _, item := range items {
		candidate := time.Date(now.Year(), now.Month(), now.Day(), item.hour, item.minute, 0, 0, r.Timezone)
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
			if err := r.Client.TurnOn(ctx); err != nil {
				return err
			}
		case "off":
			if err := r.Client.TurnOff(ctx); err != nil {
				return err
			}
		case "temp":
			if err := r.Client.SetTemperature(ctx, item.level); err != nil {
				return err
			}
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
	file, err := os.OpenFile(r.PIDFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create daemon PID file: %w", err)
	}
	_, writeErr := fmt.Fprint(file, os.Getpid())
	closeErr := file.Close()
	if writeErr != nil {
		r.removePID()
		return writeErr
	}
	if closeErr != nil {
		r.removePID()
		return closeErr
	}
	return nil
}

func (r *Runner) removePID() {
	if r.PIDFile != "" {
		_ = os.Remove(r.PIDFile)
	}
}

// ParseTemp converts a level or an F/C temperature to a heating level approximation.
func ParseTemp(s string) (int, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if strings.HasSuffix(s, "F") || strings.HasSuffix(s, "C") {
		value, err := strconv.ParseFloat(strings.TrimSpace(s[:len(s)-1]), 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return 0, fmt.Errorf("temperature must be a finite number followed by F or C")
		}
		if strings.HasSuffix(s, "F") {
			return mapFtoLevel(value), nil
		}
		return mapCtoLevel(value), nil
	}
	level, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("temperature must end with F/C or be an integer level")
	}
	if level < -100 || level > 100 {
		return 0, fmt.Errorf("level must be between -100 and 100")
	}
	return level, nil
}

// Simple linear approximations; Eight Sleep internals are non-linear, but this keeps UX consistent.
func mapFtoLevel(f float64) int {
	// Rough map 55F -> -100, 100F -> 100.
	scaled := (f-55)/(100-55)*200 - 100
	return int(min(100, max(-100, scaled)))
}

func mapCtoLevel(c float64) int {
	// 13C ~ 55F, 38C ~ 100F
	scaled := (c-13)/(38-13)*200 - 100
	return int(min(100, max(-100, scaled)))
}
