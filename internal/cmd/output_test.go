package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestSelectedOutputFields(t *testing.T) {
	for _, format := range []string{"table", "csv", "json"} {
		t.Run(format, func(t *testing.T) {
			resetViper(t)
			t.Cleanup(viper.Reset)
			viper.Set("output", format)
			viper.Set("fields", []string{"score", "date"})
			text, err := captureAwayStatus(t, func() error {
				return printRows([]string{"date", "score", "duration"}, []map[string]any{{"date": "2026-09-12", "score": 88, "duration": 3600}})
			})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(text, "duration") || strings.Contains(text, "<nil>") {
				t.Fatalf("unselected field leaked: %s", text)
			}
			switch format {
			case "csv":
				if text != "score,date\n88,2026-09-12\n" {
					t.Fatalf("CSV = %q", text)
				}
			case "table":
				if got := strings.Fields(text); strings.Join(got, ",") != "score,date,88,2026-09-12" {
					t.Fatalf("table = %q", text)
				}
			case "json":
				var rows []map[string]any
				if err := json.Unmarshal([]byte(text), &rows); err != nil {
					t.Fatal(err)
				}
				if len(rows) != 1 || len(rows[0]) != 2 || rows[0]["score"] != float64(88) {
					t.Fatalf("JSON = %s", text)
				}
			}
		})
	}
}
