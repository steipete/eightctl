package cmd

import "testing"

func TestNormalizeAlarmTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "hours and minutes", input: "08:30", want: "08:30:00"},
		{name: "seconds", input: "08:30:15", want: "08:30:15"},
		{name: "invalid", input: "tomorrow", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeAlarmTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeAlarmTime(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("normalizeAlarmTime(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
