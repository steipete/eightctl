package client

import "testing"

func TestSideAssignmentsFromDevice(t *testing.T) {
	const userA = "uid-a"
	const userB = "uid-b"

	tests := []struct {
		name        string
		left, right string
		awaySides   map[string]string
		want        map[string]string
	}{
		{
			name: "both present",
			left: userA, right: userB,
			awaySides: map[string]string{"leftUserId": userA, "rightUserId": userB},
			want:      map[string]string{userA: "left", userB: "right"},
		},
		{
			// Captured from a live Pod 2 Pro: when the left user goes away,
			// BOTH top-level slots collapse to the present (right) user while
			// awaySides retains the true mapping.
			name: "left user away collapses top-level slots to right user",
			left: userB, right: userB,
			awaySides: map[string]string{"leftUserId": userA, "rightUserId": userB},
			want:      map[string]string{userA: "left", userB: "right"},
		},
		{
			name: "right user away collapses top-level slots to left user",
			left: userA, right: userA,
			awaySides: map[string]string{"leftUserId": userA, "rightUserId": userB},
			want:      map[string]string{userA: "left", userB: "right"},
		},
		{
			name: "genuinely solo household",
			left: userA, right: userA,
			awaySides: map[string]string{"leftUserId": userA, "rightUserId": userA},
			want:      map[string]string{userA: "solo"},
		},
		{
			name: "empty top-level falls back to awaySides",
			left: "", right: "",
			awaySides: map[string]string{"leftUserId": userA, "rightUserId": userB},
			want:      map[string]string{userA: "left", userB: "right"},
		},
		{
			name: "solo with only left populated",
			left: userA, right: "",
			awaySides: nil,
			want:      map[string]string{userA: "solo"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sideAssignmentsFromDevice(tc.left, tc.right, tc.awaySides)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for uid, side := range tc.want {
				if got[uid] != side {
					t.Errorf("uid %s: got side %q, want %q (full: %v)", uid, got[uid], side, got)
				}
			}
		})
	}
}
