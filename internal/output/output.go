package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// Format represents output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatCSV   Format = "csv"
)

// PrintFields applies one field selection to both the rows and column order.
func PrintFields(format Format, headers []string, rows []map[string]any, fields []string) error {
	if len(fields) > 0 {
		headers = fields
	}
	return Print(format, headers, FilterFields(rows, fields))
}

// Print renders rows according to format.
// rows: slice of maps; headers define column order.
func Print(format Format, headers []string, rows []map[string]any) error {
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	case FormatCSV:
		w := csv.NewWriter(os.Stdout)
		if err := w.Write(headers); err != nil {
			return err
		}
		for _, row := range rows {
			line := make([]string, len(headers))
			for i, h := range headers {
				line[i] = fmt.Sprint(row[h])
			}
			if err := w.Write(line); err != nil {
				return err
			}
		}
		w.Flush()
		return w.Error()
	default:
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, strings.Join(headers, "\t"))
		for _, row := range rows {
			vals := make([]string, len(headers))
			for i, h := range headers {
				vals[i] = fmt.Sprint(row[h])
			}
			fmt.Fprintln(w, strings.Join(vals, "\t"))
		}
		return w.Flush()
	}
}

// FilterFields trims rows to selected fields; if fields empty, return rows.
func FilterFields(rows []map[string]any, fields []string) []map[string]any {
	if len(fields) == 0 {
		return rows
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		m := make(map[string]any, len(fields))
		for _, f := range fields {
			if v, ok := row[f]; ok {
				m[f] = v
			}
		}
		out = append(out, m)
	}
	return out
}
