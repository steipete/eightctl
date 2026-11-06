package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/steipete/eightctl/internal/output"
)

func TestAlarmListSoundRendersID(t *testing.T) {
	id := "rain"
	pointer := fmt.Sprint(&id)
	if strings.Contains(pointer, id) {
		t.Fatalf("fmt.Sprint of *string = %q, want a pointer address", pointer)
	}

	if got := alarmListSound(&id, output.FormatTable); got != id {
		t.Fatalf("table cell = %#v, want %q", got, id)
	}
	if got := alarmListSound(&id, output.FormatCSV); got != id {
		t.Fatalf("csv cell = %#v, want %q", got, id)
	}
	if got := alarmListSound(nil, output.FormatTable); got != "" {
		t.Fatalf("nil table cell = %#v, want empty string", got)
	}

	setRaw, err := json.Marshal(map[string]any{"sound": alarmListSound(&id, output.FormatJSON)})
	if err != nil {
		t.Fatalf("marshal set sound: %v", err)
	}
	if string(setRaw) != `{"sound":"rain"}` {
		t.Fatalf("json set sound = %s", setRaw)
	}
	nilRaw, err := json.Marshal(map[string]any{"sound": alarmListSound(nil, output.FormatJSON)})
	if err != nil {
		t.Fatalf("marshal nil sound: %v", err)
	}
	if string(nilRaw) != `{"sound":null}` {
		t.Fatalf("json nil sound = %s", nilRaw)
	}

	rows := []map[string]any{{"id": "a1", "sound": alarmListSound(&id, output.FormatTable)}}
	headers := []string{"id", "sound"}
	table := captureCmdStdout(t, func() {
		if err := output.Print(output.FormatTable, headers, rows); err != nil {
			t.Fatalf("table print: %v", err)
		}
	})
	t.Logf("table:\n%s", table)
	if !strings.Contains(table, "rain") || strings.Contains(table, pointer) {
		t.Fatalf("table = %q, want rain and not %q", table, pointer)
	}
	csv := captureCmdStdout(t, func() {
		if err := output.Print(output.FormatCSV, headers, []map[string]any{{"id": "a1", "sound": alarmListSound(&id, output.FormatCSV)}}); err != nil {
			t.Fatalf("csv print: %v", err)
		}
	})
	t.Logf("csv:\n%s", csv)
	if !strings.Contains(csv, "a1,rain") || strings.Contains(csv, pointer) {
		t.Fatalf("csv = %q, want a1,rain and not %q", csv, pointer)
	}
}

func captureCmdStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(out)
}
