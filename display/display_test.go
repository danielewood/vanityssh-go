package display

import "testing"

func TestFormatCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		n    int64
		want string
	}{
		{name: "zero", n: 0, want: "0"},
		{name: "single digit", n: 7, want: "7"},
		{name: "below threshold", n: 999, want: "999"},
		{name: "at threshold", n: 1000, want: "1,000"},
		{name: "five digits", n: 12345, want: "12,345"},
		{name: "millions", n: 1234567, want: "1,234,567"},
		{name: "billions", n: 1234567890, want: "1,234,567,890"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatCount(tt.n)
			if got != tt.want {
				t.Errorf("FormatCount(%d) = %q, want %q", tt.n, got, tt.want)
			}
		})
	}
}

func TestIsTTY(t *testing.T) {
	t.Parallel()

	// In test environment, stdout is not a terminal
	if IsTTY() {
		t.Error("IsTTY() = true in test environment, want false")
	}
}
